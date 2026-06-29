package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
)

type conversationSink interface {
	Emit(payload []byte) error
	Close() error
}

func newConversationSink(cfg config) (conversationSink, error) {
	switch cfg.outputSink {
	case "", outputSinkStdout:
		return nil, nil
	case outputSinkHTTP:
		endpoint, token := resolveHTTPSinkAuth(cfg)
		return &httpConversationSink{
			endpoint:       endpoint,
			agentToken:     token,
			client:         &http.Client{Timeout: cfg.httpTimeout},
			maxRetries:     cfg.httpMaxRetries,
			initialBackoff: cfg.httpRetryDelay,
			deadLetterFile: cfg.deadLetterFile,
		}, nil
	case outputSinkKafka:
		producer, err := kafka.NewProducer(&kafka.ConfigMap{
			"bootstrap.servers": cfg.outputBootstrap,
		})
		if err != nil {
			return nil, err
		}
		return &kafkaConversationSink{
			producer:       producer,
			topic:          cfg.outputTopic,
			timeout:        cfg.httpTimeout,
			deadLetterFile: cfg.deadLetterFile,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported output sink %q", cfg.outputSink)
	}
}

type httpConversationSink struct {
	endpoint       string
	agentToken     string
	client         *http.Client
	maxRetries     int
	initialBackoff time.Duration
	deadLetterFile string
}

func (s *httpConversationSink) Emit(payload []byte) error {
	var lastErr error
	backoff := s.initialBackoff

	for attempt := 0; attempt <= s.maxRetries; attempt++ {
		if attempt > 0 && backoff > 0 {
			time.Sleep(backoff)
			backoff *= 2
		}

		err := s.post(payload)
		if err == nil {
			return nil
		}
		lastErr = err
		if !retryableSinkError(err) {
			break
		}
	}

	writeErr := writeDeadLetter(s.deadLetterFile, outputSinkHTTP, lastErr, payload)
	if writeErr != nil {
		return fmt.Errorf("%w; failed to write dead letter: %v", lastErr, writeErr)
	}
	return lastErr
}

func (s *httpConversationSink) Close() error {
	return nil
}

func (s *httpConversationSink) post(payload []byte) error {
	req, err := http.NewRequest(http.MethodPost, s.endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.agentToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return httpSinkStatusError{
		statusCode: resp.StatusCode,
		body:       strings.TrimSpace(string(body)),
	}
}

type httpSinkStatusError struct {
	statusCode int
	body       string
}

func (e httpSinkStatusError) Error() string {
	if e.body == "" {
		return fmt.Sprintf("backend ingestion returned HTTP %d", e.statusCode)
	}
	return fmt.Sprintf("backend ingestion returned HTTP %d: %s", e.statusCode, e.body)
}

func retryableSinkError(err error) bool {
	var statusErr httpSinkStatusError
	if errors.As(err, &statusErr) {
		return statusErr.statusCode == http.StatusTooManyRequests || statusErr.statusCode >= 500
	}
	return true
}

type kafkaConversationSink struct {
	producer       *kafka.Producer
	topic          string
	timeout        time.Duration
	deadLetterFile string
}

func (s *kafkaConversationSink) Emit(payload []byte) error {
	delivery := make(chan kafka.Event, 1)
	err := s.producer.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &s.topic, Partition: kafka.PartitionAny},
		Value:          payload,
	}, delivery)
	if err != nil {
		_ = writeDeadLetter(s.deadLetterFile, outputSinkKafka, err, payload)
		return err
	}

	select {
	case event := <-delivery:
		message, ok := event.(*kafka.Message)
		if !ok {
			err := fmt.Errorf("unexpected kafka delivery event %T", event)
			_ = writeDeadLetter(s.deadLetterFile, outputSinkKafka, err, payload)
			return err
		}
		if message.TopicPartition.Error != nil {
			_ = writeDeadLetter(s.deadLetterFile, outputSinkKafka, message.TopicPartition.Error, payload)
			return message.TopicPartition.Error
		}
		return nil
	case <-time.After(s.timeout):
		err := fmt.Errorf("kafka delivery timed out after %s", s.timeout)
		_ = writeDeadLetter(s.deadLetterFile, outputSinkKafka, err, payload)
		return err
	}
}

func (s *kafkaConversationSink) Close() error {
	if s.producer == nil {
		return nil
	}
	s.producer.Flush(5000)
	s.producer.Close()
	return nil
}

type sinkDeadLetter struct {
	CreatedAt string          `json:"created_at"`
	Sink      string          `json:"sink"`
	Error     string          `json:"error"`
	Payload   json.RawMessage `json:"payload"`
}

func writeDeadLetter(path string, sink string, emitErr error, payload []byte) error {
	if path == "" {
		return nil
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}

	record := sinkDeadLetter{
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Sink:      sink,
		Error:     emitErr.Error(),
		Payload:   json.RawMessage(payload),
	}
	line, err := json.Marshal(record)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(append(line, '\n')); err != nil {
		return err
	}
	return nil
}

// resolveHTTPSinkAuth returns the (endpoint, token) to use for the HTTP sink.
// New mode (KARAXYS_INGEST_URL + KARAXYS_ACCOUNT_TOKEN) takes priority.
// Legacy mode (KARAXYS_BACKEND_URL + KARAXYS_AGENT_TOKEN) is the fallback.
func resolveHTTPSinkAuth(cfg config) (endpoint, token string) {
	if cfg.ingestURL != "" && cfg.accountToken != "" {
		return cfg.ingestURL, cfg.accountToken
	}
	return backendIngestEndpoint(cfg.backendURL), cfg.agentToken
}

func backendIngestEndpoint(baseURL string) string {
	trimmed := strings.TrimRight(baseURL, "/")
	if strings.HasSuffix(trimmed, "/v1/ingest/conversations") {
		return trimmed
	}
	return trimmed + "/v1/ingest/conversations"
}
