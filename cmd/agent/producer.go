package main

import (
	"errors"
	"fmt"
	"log"
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
	producer *kafka.Producer
	topic    string
	mode     backpressureMode
	queue    chan queuedKafkaMessage
	stats    *agentStats
	stop     chan struct{}
	done     chan struct{}
}

func parseBackpressureMode(raw string) (backpressureMode, error) {
	switch backpressureMode(raw) {
	case backpressureBestEffort, backpressureStrict, backpressureDropNewest, backpressureDropOldest:
		return backpressureMode(raw), nil
	default:
		return "", fmt.Errorf("unsupported backpressure mode %q", raw)
	}
}

func newQueuedProducer(producer *kafka.Producer, topic string, mode backpressureMode, queueEvents int, stats *agentStats) *queuedProducer {
	if queueEvents <= 0 {
		queueEvents = 1
	}
	qp := &queuedProducer{
		producer: producer,
		topic:    topic,
		mode:     mode,
		queue:    make(chan queuedKafkaMessage, queueEvents),
		stats:    stats,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
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
			}
		}
	case backpressureDropNewest, backpressureBestEffort:
		select {
		case q.queue <- msg:
			atomic.AddUint64(&q.stats.localQueueEnqueued, 1)
		default:
			atomic.AddUint64(&q.stats.localQueueDropped, 1)
		}
	}
}

func (q *queuedProducer) run() {
	defer close(q.done)
	for {
		select {
		case <-q.stop:
			q.drain(5 * time.Second)
			return
		case msg := <-q.queue:
			q.produce(msg)
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
				log.Printf("producer queue drain timed out; dropping remaining=%d", remaining)
			}
			return
		default:
			return
		}
	}
}

func (q *queuedProducer) produce(msg queuedKafkaMessage) {
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
}

func (q *queuedProducer) close() {
	close(q.stop)
	<-q.done
}

func (q *queuedProducer) depth() int {
	return len(q.queue)
}

func cloneBytes(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
