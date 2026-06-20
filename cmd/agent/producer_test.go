package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDiskSpoolWriteReadAndTruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-spool.jsonl")
	spool, err := newDiskSpool(path, 1024*1024)
	if err != nil {
		t.Fatalf("create spool: %v", err)
	}

	msg := queuedKafkaMessage{key: []byte("key"), value: []byte(`{"ok":true}`)}
	if err := spool.write("test", msg); err != nil {
		t.Fatalf("write spool: %v", err)
	}

	messages, err := spool.readAll()
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected one spooled message, got %d", len(messages))
	}
	if string(messages[0].key) != "key" || string(messages[0].value) != `{"ok":true}` {
		t.Fatalf("unexpected spooled message: key=%q value=%q", messages[0].key, messages[0].value)
	}

	if err := spool.truncate(); err != nil {
		t.Fatalf("truncate spool: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read truncated spool: %v", err)
	}
	if len(raw) != 0 {
		t.Fatalf("expected empty spool after truncate, got %q", string(raw))
	}
}

func TestDiskSpoolEnforcesMaxBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-spool.jsonl")
	spool, err := newDiskSpool(path, 16)
	if err != nil {
		t.Fatalf("create spool: %v", err)
	}
	if err := os.WriteFile(path, []byte("0123456789abcdef"), 0o600); err != nil {
		t.Fatalf("seed spool: %v", err)
	}
	if err := spool.write("test", queuedKafkaMessage{value: []byte("new")}); err != nil {
		t.Fatalf("write spool: %v", err)
	}
	messages, err := spool.readAll()
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	if len(messages) != 1 || string(messages[0].value) != "new" {
		t.Fatalf("expected only new message after max-byte enforcement, got %+v", messages)
	}
}

func TestReplaySpoolRetainsMessagesThatDoNotFitQueue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-spool.jsonl")
	spool, err := newDiskSpool(path, 1024*1024)
	if err != nil {
		t.Fatalf("create spool: %v", err)
	}
	if err := spool.write("seed", queuedKafkaMessage{key: []byte("one"), value: []byte("1")}); err != nil {
		t.Fatalf("write first spool record: %v", err)
	}
	if err := spool.write("seed", queuedKafkaMessage{key: []byte("two"), value: []byte("2")}); err != nil {
		t.Fatalf("write second spool record: %v", err)
	}

	q := &queuedProducer{
		queue: make(chan queuedKafkaMessage, 1),
		stats: &agentStats{},
		spool: spool,
	}
	q.replaySpool()

	if len(q.queue) != 1 {
		t.Fatalf("expected one message replayed to queue, got %d", len(q.queue))
	}
	retained, err := spool.readAll()
	if err != nil {
		t.Fatalf("read retained spool: %v", err)
	}
	if len(retained) != 1 || string(retained[0].key) != "two" || string(retained[0].value) != "2" {
		t.Fatalf("expected second message retained in spool, got %+v", retained)
	}
}

func TestQueuedProducerSpoolMessageTracksStatsAndBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-spool.jsonl")
	spool, err := newDiskSpool(path, 1024*1024)
	if err != nil {
		t.Fatalf("create spool: %v", err)
	}
	stats := &agentStats{}
	q := &queuedProducer{stats: stats, spool: spool}

	q.spoolMessage("delivery_failure", queuedKafkaMessage{key: []byte("key"), value: []byte("value")})

	if stats.spoolWrites != 1 {
		t.Fatalf("spoolWrites = %d, want 1", stats.spoolWrites)
	}
	if stats.spoolWriteErrors != 0 {
		t.Fatalf("spoolWriteErrors = %d, want 0", stats.spoolWriteErrors)
	}
	if got := q.spoolBytes(); got <= 0 {
		t.Fatalf("spoolBytes = %d, want > 0", got)
	}
}

func TestReplaySpoolCountsReplayedAndRetained(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-spool.jsonl")
	spool, err := newDiskSpool(path, 1024*1024)
	if err != nil {
		t.Fatalf("create spool: %v", err)
	}
	if err := spool.write("seed", queuedKafkaMessage{key: []byte("one"), value: []byte("1")}); err != nil {
		t.Fatalf("write first spool record: %v", err)
	}
	if err := spool.write("seed", queuedKafkaMessage{key: []byte("two"), value: []byte("2")}); err != nil {
		t.Fatalf("write second spool record: %v", err)
	}

	stats := &agentStats{}
	q := &queuedProducer{
		queue: make(chan queuedKafkaMessage, 1),
		stats: stats,
		spool: spool,
	}
	q.replaySpool()

	if stats.spoolReplayed != 1 || stats.spoolRetained != 1 {
		t.Fatalf("unexpected replay stats: replayed=%d retained=%d", stats.spoolReplayed, stats.spoolRetained)
	}
	if stats.spoolWrites != 1 {
		t.Fatalf("retained message should be written back once, spoolWrites=%d", stats.spoolWrites)
	}
}

func TestQueuedProducerSpoolsWhileBrokerCircuitOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-spool.jsonl")
	spool, err := newDiskSpool(path, 1024*1024)
	if err != nil {
		t.Fatalf("create spool: %v", err)
	}
	stats := &agentStats{}
	q := &queuedProducer{
		stats:                  stats,
		spool:                  spool,
		circuitBreakerDuration: time.Minute,
	}

	q.markBrokerUnavailable(assertionError("broker down"))
	q.produce(queuedKafkaMessage{key: []byte("key"), value: []byte("value")})

	if stats.brokerUnavailableEvents != 1 {
		t.Fatalf("brokerUnavailableEvents = %d, want 1", stats.brokerUnavailableEvents)
	}
	if stats.brokerCircuitSpool != 1 {
		t.Fatalf("brokerCircuitSpool = %d, want 1", stats.brokerCircuitSpool)
	}
	if stats.produceAttempts != 0 {
		t.Fatalf("produceAttempts = %d, want 0", stats.produceAttempts)
	}
	messages, err := spool.readAll()
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	if len(messages) != 1 || string(messages[0].value) != "value" {
		t.Fatalf("expected message in spool, got %+v", messages)
	}

	q.markBrokerAvailable()
	if q.brokerUnavailable() {
		t.Fatalf("broker circuit should be closed")
	}
}

type assertionError string

func (e assertionError) Error() string {
	return string(e)
}
