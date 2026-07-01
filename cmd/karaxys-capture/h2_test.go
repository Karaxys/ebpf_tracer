package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type fakeSink struct {
	payloads [][]byte
}

func (s *fakeSink) Emit(payload []byte) error {
	s.payloads = append(s.payloads, append([]byte(nil), payload...))
	return nil
}

func (s *fakeSink) Close() error { return nil }

func encodeHeaders(t *testing.T, fields []hpack.HeaderField) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, f := range fields {
		if err := enc.WriteField(f); err != nil {
			t.Fatalf("hpack encode: %v", err)
		}
	}
	return buf.Bytes()
}

func buildH2ClientBytes(t *testing.T, streamID uint32, reqBody []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.Write(h2Preface)

	fr := http2.NewFramer(&buf, nil)
	headerBlock := encodeHeaders(t, []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: "/api/secure"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":scheme", Value: "https"},
		{Name: "content-type", Value: "application/json"},
	})
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: headerBlock,
		EndHeaders:    true,
	}); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	if err := fr.WriteData(streamID, true, reqBody); err != nil {
		t.Fatalf("write data: %v", err)
	}
	return buf.Bytes()
}

func buildH2ServerBytes(t *testing.T, streamID uint32, respBody []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	fr := http2.NewFramer(&buf, nil)
	headerBlock := encodeHeaders(t, []hpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "application/json"},
	})
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: headerBlock,
		EndHeaders:    true,
	}); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	if err := fr.WriteData(streamID, true, respBody); err != nil {
		t.Fatalf("write data: %v", err)
	}
	return buf.Bytes()
}

// chunk splits data into pieces to simulate eBPF delivering partial syscall
// reads/writes rather than whole frames at once.
func chunk(data []byte, size int) [][]byte {
	var out [][]byte
	for len(data) > 0 {
		n := size
		if n > len(data) {
			n = len(data)
		}
		out = append(out, data[:n])
		data = data[n:]
	}
	return out
}

func TestDrainH2_FullExchange(t *testing.T) {
	reqBody := []byte(`{"hello":"world"}`)
	respBody := []byte(`{"status":"ok"}`)

	clientBytes := buildH2ClientBytes(t, 1, reqBody)
	serverBytes := buildH2ServerBytes(t, 1, respBody)

	sink := &fakeSink{}
	cfg := config{
		maxBodyBytes:   1024 * 1024,
		maxStreamBytes: 8 * 1024 * 1024,
		sink:           sink,
	}
	stats := &processingStats{}
	store := newSessionStore(time.Minute)

	pid, fd := uint32(100), uint32(5)
	seq := uint32(0)
	send := func(dir uint8, data []byte) {
		for _, part := range chunk(data, 11) { // deliberately awkward split size
			processEvent(store, cfg, stats, CaptureEvent{
				EventType: eventTypeData,
				PID:       pid,
				FD:        fd,
				Direction: dir,
				Seq:       seq,
				Size:      uint32(len(part)),
				Payload:   part,
			})
			seq++
		}
	}

	// Interleave client (read) and server (write) bytes like a real capture.
	send(directionRead, clientBytes)
	send(directionWrite, serverBytes)

	if len(sink.payloads) != 1 {
		t.Fatalf("expected 1 emitted conversation, got %d", len(sink.payloads))
	}

	var got NormalizedConversation
	if err := json.Unmarshal(sink.payloads[0], &got); err != nil {
		t.Fatalf("unmarshal emitted payload: %v", err)
	}

	if got.HTTP.Request.Method != "POST" {
		t.Errorf("method = %q, want POST", got.HTTP.Request.Method)
	}
	if got.HTTP.Request.Path != "/api/secure" {
		t.Errorf("path = %q, want /api/secure", got.HTTP.Request.Path)
	}
	if got.HTTP.Request.Host != "example.com" {
		t.Errorf("host = %q, want example.com", got.HTTP.Request.Host)
	}
	if got.HTTP.Request.Body != prettyMaybeJSON(string(reqBody)) {
		t.Errorf("request body = %q, want %q", got.HTTP.Request.Body, prettyMaybeJSON(string(reqBody)))
	}
	if got.HTTP.Response.StatusCode == nil || *got.HTTP.Response.StatusCode != 200 {
		t.Errorf("status code = %v, want 200", got.HTTP.Response.StatusCode)
	}
	if got.HTTP.Response.Body != prettyMaybeJSON(string(respBody)) {
		t.Errorf("response body = %q, want %q", got.HTTP.Response.Body, prettyMaybeJSON(string(respBody)))
	}

	// Re-draining an already-emitted stream must not duplicate the emission.
	state, _ := store.get(sessionKey(CaptureEvent{PID: pid, FD: fd}))
	if state == nil {
		t.Fatal("expected session state to exist")
	}
	state.mu.Lock()
	n := drainStream(cfg, stats, state, false)
	state.mu.Unlock()
	if n != 0 {
		t.Errorf("re-drain emitted %d new conversations, want 0", n)
	}
	if len(sink.payloads) != 1 {
		t.Errorf("sink has %d payloads after re-drain, want 1", len(sink.payloads))
	}
}
