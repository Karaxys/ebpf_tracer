package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
)

type backpressureMode string

const (
	backpressureBestEffort backpressureMode = "best-effort"
	backpressureStrict     backpressureMode = "strict"
	backpressureDropNewest backpressureMode = "drop-newest"
	backpressureDropOldest backpressureMode = "drop-oldest"
)

type queuedKafkaMessage struct {
	key   []byte
	value []byte
}

type queuedProducer struct {
	producer               *kafka.Producer
	topic                  string
	mode                   backpressureMode
	queue                  chan queuedKafkaMessage
	stats                  *agentStats
	spool                  *diskSpool
	replayInterval         time.Duration
	circuitBreakerDuration time.Duration
	brokerDownUntil        int64
	stop                   chan struct{}
	done                   chan struct{}
}

type diskSpool struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
}

type spooledKafkaMessage struct {
	CreatedAt string `json:"created_at"`
	Reason    string `json:"reason"`
	Key       string `json:"key,omitempty"`
	Value     string `json:"value"`
}

func parseBackpressureMode(raw string) (backpressureMode, error) {
	switch backpressureMode(raw) {
	case backpressureBestEffort, backpressureStrict, backpressureDropNewest, backpressureDropOldest:
		return backpressureMode(raw), nil
	default:
		return "", fmt.Errorf("unsupported backpressure mode %q", raw)
	}
}

func newQueuedProducer(producer *kafka.Producer, topic string, mode backpressureMode, queueEvents int, stats *agentStats, spool *diskSpool, circuitBreakerDuration time.Duration) *queuedProducer {
	if queueEvents <= 0 {
		queueEvents = 1
	}
	qp := &queuedProducer{
		producer:               producer,
		topic:                  topic,
		mode:                   mode,
		queue:                  make(chan queuedKafkaMessage, queueEvents),
		stats:                  stats,
		spool:                  spool,
		replayInterval:         30 * time.Second,
		circuitBreakerDuration: circuitBreakerDuration,
		stop:                   make(chan struct{}),
		done:                   make(chan struct{}),
	}
	qp.replaySpool()
	go qp.run()
	return qp
}

func (q *queuedProducer) submit(key, value []byte) {
	msg := queuedKafkaMessage{key: cloneBytes(key), value: cloneBytes(value)}

	switch q.mode {
	case backpressureStrict:
		q.queue <- msg
		atomic.AddUint64(&q.stats.localQueueEnqueued, 1)
	case backpressureDropOldest:
		select {
		case q.queue <- msg:
			atomic.AddUint64(&q.stats.localQueueEnqueued, 1)
		default:
			select {
			case <-q.queue:
				atomic.AddUint64(&q.stats.localQueueDropped, 1)
			default:
			}
			select {
			case q.queue <- msg:
				atomic.AddUint64(&q.stats.localQueueEnqueued, 1)
			default:
				atomic.AddUint64(&q.stats.localQueueDropped, 1)
				q.spoolMessage("local_queue_full", msg)
			}
		}
	case backpressureDropNewest, backpressureBestEffort:
		select {
		case q.queue <- msg:
			atomic.AddUint64(&q.stats.localQueueEnqueued, 1)
		default:
			atomic.AddUint64(&q.stats.localQueueDropped, 1)
			q.spoolMessage("local_queue_full", msg)
		}
	}
}

func (q *queuedProducer) run() {
	defer close(q.done)
	replayTicker := time.NewTicker(q.replayInterval)
	defer replayTicker.Stop()
	for {
		select {
		case <-q.stop:
			q.drain(5 * time.Second)
			return
		case msg := <-q.queue:
			q.produce(msg)
		case <-replayTicker.C:
			q.replaySpool()
		}
	}
}

func (q *queuedProducer) drain(maxWait time.Duration) {
	deadline := time.After(maxWait)
	for {
		select {
		case msg := <-q.queue:
			q.produce(msg)
		case <-deadline:
			remaining := len(q.queue)
			if remaining > 0 {
				atomic.AddUint64(&q.stats.localQueueDropped, uint64(remaining))
				for {
					select {
					case msg := <-q.queue:
						q.spoolMessage("drain_timeout", msg)
					default:
						log.Printf("producer queue drain timed out; spooled remaining=%d", remaining)
						return
					}
				}
			}
			return
		default:
			return
		}
	}
}

func (q *queuedProducer) produce(msg queuedKafkaMessage) {
	if q.brokerUnavailable() {
		if q.stats != nil {
			atomic.AddUint64(&q.stats.brokerCircuitSpool, 1)
		}
		q.spoolMessage("broker_unavailable", msg)
		return
	}

	atomic.AddUint64(&q.stats.produceAttempts, 1)
	err := q.producer.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &q.topic, Partition: kafka.PartitionAny},
		Key:            msg.key,
		Value:          msg.value,
	}, nil)
	if err == nil {
		return
	}

	atomic.AddUint64(&q.stats.produceErrors, 1)
	var kafkaErr kafka.Error
	if errors.As(err, &kafkaErr) && kafkaErr.Code() == kafka.ErrQueueFull {
		atomic.AddUint64(&q.stats.produceQueueFull, 1)
	}
	log.Printf("Failed to produce to Kafka: %v", err)
	q.spoolMessage("produce_error", msg)
}

func (q *queuedProducer) close() {
	close(q.stop)
	<-q.done
}

func (q *queuedProducer) markBrokerUnavailable(reason error) {
	if q == nil || q.circuitBreakerDuration <= 0 {
		return
	}
	wasUnavailable := q.brokerUnavailable()
	until := time.Now().Add(q.circuitBreakerDuration).UnixNano()
	for {
		current := atomic.LoadInt64(&q.brokerDownUntil)
		if current >= until {
			break
		}
		if atomic.CompareAndSwapInt64(&q.brokerDownUntil, current, until) {
			break
		}
	}
	if !wasUnavailable {
		if q.stats != nil {
			atomic.AddUint64(&q.stats.brokerUnavailableEvents, 1)
		}
		log.Printf("Kafka broker circuit opened for %s: %v", q.circuitBreakerDuration, reason)
	}
}

func (q *queuedProducer) markBrokerAvailable() {
	if q == nil {
		return
	}
	if atomic.SwapInt64(&q.brokerDownUntil, 0) > time.Now().UnixNano() {
		log.Printf("Kafka broker circuit closed after successful delivery")
	}
}

func (q *queuedProducer) brokerUnavailable() bool {
	if q == nil {
		return false
	}
	until := atomic.LoadInt64(&q.brokerDownUntil)
	return until > 0 && time.Now().UnixNano() < until
}

func (q *queuedProducer) depth() int {
	return len(q.queue)
}

func (q *queuedProducer) spoolMessage(reason string, msg queuedKafkaMessage) {
	if q == nil || q.spool == nil {
		return
	}
	if err := q.spool.write(reason, msg); err != nil {
		if q.stats != nil {
			atomic.AddUint64(&q.stats.spoolWriteErrors, 1)
		}
		log.Printf("Failed to spool Kafka message: %v", err)
		return
	}
	if q.stats != nil {
		atomic.AddUint64(&q.stats.spoolWrites, 1)
	}
}

func (q *queuedProducer) replaySpool() {
	if q == nil || q.spool == nil {
		return
	}
	messages, err := q.spool.drainAll()
	if err != nil {
		log.Printf("Failed to read Kafka spool: %v", err)
		return
	}
	if len(messages) == 0 {
		return
	}
	retained := make([]queuedKafkaMessage, 0)
	for _, msg := range messages {
		select {
		case q.queue <- msg:
			atomic.AddUint64(&q.stats.localQueueEnqueued, 1)
		default:
			retained = append(retained, msg)
		}
	}
	for _, msg := range retained {
		q.spoolMessage("replay_queue_full", msg)
	}
	if q.stats != nil {
		atomic.AddUint64(&q.stats.spoolReplayed, uint64(len(messages)-len(retained)))
		atomic.AddUint64(&q.stats.spoolRetained, uint64(len(retained)))
	}
	log.Printf("Replayed Kafka spool messages=%d retained=%d", len(messages)-len(retained), len(retained))
}

func (q *queuedProducer) spoolBytes() int64 {
	if q == nil || q.spool == nil {
		return 0
	}
	size, err := q.spool.size()
	if err != nil {
		return 0
	}
	return size
}

func newDiskSpool(path string, maxBytes int64) (*diskSpool, error) {
	path = filepath.Clean(path)
	if path == "." || path == "" {
		return nil, nil
	}
	if maxBytes <= 0 {
		maxBytes = 128 * 1024 * 1024
	}
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	return &diskSpool{path: path, maxBytes: maxBytes}, nil
}

func (s *diskSpool) write(reason string, msg queuedKafkaMessage) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.enforceLimitLocked(); err != nil {
		return err
	}
	record := spooledKafkaMessage{
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Reason:    reason,
		Key:       base64.StdEncoding.EncodeToString(msg.key),
		Value:     base64.StdEncoding.EncodeToString(msg.value),
	}
	line, err := json.Marshal(record)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(append(line, '\n')); err != nil {
		return err
	}
	return nil
}

func (s *diskSpool) readAll() ([]queuedKafkaMessage, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readAllLocked()
}

func (s *diskSpool) drainAll() ([]queuedKafkaMessage, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	messages, err := s.readAllLocked()
	if err != nil {
		return nil, err
	}
	if len(messages) == 0 {
		return nil, nil
	}
	if err := os.WriteFile(s.path, nil, 0o600); err != nil {
		return nil, err
	}
	return messages, nil
}

func (s *diskSpool) readAllLocked() ([]queuedKafkaMessage, error) {
	if s == nil {
		return nil, nil
	}

	file, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var messages []queuedKafkaMessage
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		var record spooledKafkaMessage
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			continue
		}
		value, err := base64.StdEncoding.DecodeString(record.Value)
		if err != nil || len(value) == 0 {
			continue
		}
		key, _ := base64.StdEncoding.DecodeString(record.Key)
		messages = append(messages, queuedKafkaMessage{key: key, value: value})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return messages, nil
}

func (s *diskSpool) size() (int64, error) {
	if s == nil {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	info, err := os.Stat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func (s *diskSpool) truncate() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.WriteFile(s.path, nil, 0o600)
}

func (s *diskSpool) enforceLimitLocked() error {
	info, err := os.Stat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Size() < s.maxBytes {
		return nil
	}
	return os.WriteFile(s.path, nil, 0o600)
}

func cloneBytes(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
