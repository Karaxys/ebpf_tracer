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
)

// ── Interface ─────────────────────────────────────────────────────────────────

type conversationSink interface {
	Emit(payload []byte) error
	Close() error
}

func newHTTPSink(ingestURL, accountToken string, timeout time.Duration, maxRetries int, retryDelay time.Duration, deadLetterFile string) *httpConversationSink {
	return &httpConversationSink{
		endpoint:       ingestURL,
		agentToken:     accountToken,
		client:         &http.Client{Timeout: timeout},
		maxRetries:     maxRetries,
		initialBackoff: retryDelay,
		deadLetterFile: deadLetterFile,
	}
}

// ── HTTP sink ─────────────────────────────────────────────────────────────────

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

	_ = writeDeadLetter(s.deadLetterFile, lastErr, payload)
	return lastErr
}

func (s *httpConversationSink) Close() error { return nil }

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
	return httpSinkStatusError{statusCode: resp.StatusCode, body: strings.TrimSpace(string(body))}
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

// ── Dead-letter file ──────────────────────────────────────────────────────────

type sinkDeadLetter struct {
	CreatedAt string          `json:"created_at"`
	Error     string          `json:"error"`
	Payload   json.RawMessage `json:"payload"`
}

func writeDeadLetter(path string, emitErr error, payload []byte) error {
	if path == "" || emitErr == nil {
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
		Error:     emitErr.Error(),
		Payload:   json.RawMessage(payload),
	}
	line, err := json.Marshal(record)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(append(line, '\n'))
	return err
}
