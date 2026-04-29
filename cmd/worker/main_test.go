package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestParseOneRequestComplete(t *testing.T) {
	raw := []byte("POST /submit HTTP/1.1\r\nHost: example.local\r\nContent-Length: 11\r\n\r\nhello world")

	req, body, consumed, ok := parseOneRequest(raw, 1024)
	if !ok {
		t.Fatalf("expected parse success")
	}
	if req.Method != http.MethodPost {
		t.Fatalf("unexpected method: %s", req.Method)
	}
	if body != "hello world" {
		t.Fatalf("unexpected body: %q", body)
	}
	if consumed != len(raw) {
		t.Fatalf("unexpected consumed bytes: got=%d want=%d", consumed, len(raw))
	}
}

func TestParseOneRequestIncompleteBody(t *testing.T) {
	raw := []byte("POST /submit HTTP/1.1\r\nHost: example.local\r\nContent-Length: 11\r\n\r\nhello")

	_, _, consumed, ok := parseOneRequest(raw, 1024)
	if ok {
		t.Fatalf("expected parse failure for incomplete body")
	}
	if consumed != 0 {
		t.Fatalf("unexpected consumed bytes: %d", consumed)
	}
}

func TestParseOneRequestTruncatedBodyMarker(t *testing.T) {
	raw := []byte("POST /submit HTTP/1.1\r\nHost: example.local\r\nContent-Length: 11\r\n\r\nhello world")

	_, body, _, ok := parseOneRequest(raw, 4)
	if !ok {
		t.Fatalf("expected parse success")
	}
	if body != "hell\n[truncated]" {
		t.Fatalf("unexpected truncated body: %q", body)
	}
}

func TestParseOneResponseComplete(t *testing.T) {
	req := &http.Request{Method: http.MethodGet}
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")

	resp, body, consumed, ok := parseOneResponse(raw, req, 1024, false)
	if !ok {
		t.Fatalf("expected parse success")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d", resp.StatusCode)
	}
	if body != "hello" {
		t.Fatalf("unexpected body: %q", body)
	}
	if consumed != len(raw) {
		t.Fatalf("unexpected consumed bytes: got=%d want=%d", consumed, len(raw))
	}
}

func TestParseOneResponseIncompleteBody(t *testing.T) {
	req := &http.Request{Method: http.MethodGet}
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello")

	_, _, consumed, ok := parseOneResponse(raw, req, 1024, false)
	if ok {
		t.Fatalf("expected parse failure for incomplete response body")
	}
	if consumed != 0 {
		t.Fatalf("unexpected consumed bytes: %d", consumed)
	}
}

func TestParseOneResponseWaitsForCloseDelimitedBody(t *testing.T) {
	req := &http.Request{Method: http.MethodGet}
	raw := []byte("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\nhello")

	_, _, consumed, ok := parseOneResponse(raw, req, 1024, false)
	if ok {
		t.Fatalf("expected parse failure for close-delimited body")
	}
	if consumed != 0 {
		t.Fatalf("unexpected consumed bytes: %d", consumed)
	}
}

func TestParseOneResponseNoBodyStatus(t *testing.T) {
	req := &http.Request{Method: http.MethodGet}
	raw := []byte("HTTP/1.1 204 No Content\r\nDate: Sat, 25 Apr 2026 12:00:00 GMT\r\n\r\n")

	resp, body, consumed, ok := parseOneResponse(raw, req, 1024, false)
	if !ok {
		t.Fatalf("expected parse success for no-body response")
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected status code: %d", resp.StatusCode)
	}
	if body != "" {
		t.Fatalf("unexpected body: %q", body)
	}
	if consumed != len(raw) {
		t.Fatalf("unexpected consumed bytes: got=%d want=%d", consumed, len(raw))
	}
}

func TestSyncRequestBufferDropsPrefix(t *testing.T) {
	data := []byte("noise noise GET /v1 HTTP/1.1\r\n")
	aligned, dropped := syncRequestBuffer(data)

	if dropped <= 0 {
		t.Fatalf("expected dropped prefix")
	}
	if !bytes.HasPrefix(aligned, []byte("GET ")) {
		t.Fatalf("expected aligned request start, got: %q", string(aligned))
	}
}

func TestSyncResponseBufferDropsPrefix(t *testing.T) {
	data := []byte("xyzHTTP/1.1 200 OK\r\n")
	aligned, dropped := syncResponseBuffer(data)

	if dropped != 3 {
		t.Fatalf("unexpected dropped bytes: %d", dropped)
	}
	if !bytes.HasPrefix(aligned, []byte("HTTP/1.")) {
		t.Fatalf("expected aligned response start, got: %q", string(aligned))
	}
}

func TestSyncRequestBufferKeepsProbeWindow(t *testing.T) {
	data := []byte("abcdefghijklmnopq")
	aligned, dropped := syncRequestBuffer(data)

	if len(aligned) != requestStartProbeWindow {
		t.Fatalf("unexpected aligned len: got=%d want=%d", len(aligned), requestStartProbeWindow)
	}
	if dropped != 1 {
		t.Fatalf("unexpected dropped bytes: %d", dropped)
	}
}

func TestProcessEventEmitsStructuredConversation(t *testing.T) {
	var out bytes.Buffer
	cfg := testConfig(&out)
	store := newSessionStore(cfg.sessionTTL)
	stats := &workerStats{}

	processEvent(store, cfg, stats, testEvent(1, directionRead, []byte("GET /users/v1 HTTP/1.1\r\nHost: 127.0.0.1:3000\r\n\r\n")))
	processEvent(store, cfg, stats, testEvent(2, directionWrite, []byte("HTTP/1.1 200 OK\r\nContent-Length: 14\r\nContent-Type: application/json\r\n\r\n{\"users\": []}\n")))

	conversation := decodeSingleConversation(t, out.String())
	if conversation.Method != http.MethodGet {
		t.Fatalf("unexpected method: %s", conversation.Method)
	}
	if conversation.Host != "127.0.0.1:3000" {
		t.Fatalf("unexpected host: %s", conversation.Host)
	}
	if conversation.Path != "/users/v1" {
		t.Fatalf("unexpected path: %s", conversation.Path)
	}
	if conversation.RespStatus != "200 OK" {
		t.Fatalf("unexpected response status: %s", conversation.RespStatus)
	}
	if atomic.LoadUint64(&stats.parsed) != 1 {
		t.Fatalf("unexpected parsed count: %d", stats.parsed)
	}
}

func TestProcessEventHandlesResponseBeforeRequest(t *testing.T) {
	var out bytes.Buffer
	cfg := testConfig(&out)
	store := newSessionStore(cfg.sessionTTL)
	stats := &workerStats{}

	processEvent(store, cfg, stats, testEvent(2, directionWrite, []byte("HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n{}")))
	processEvent(store, cfg, stats, testEvent(1, directionRead, []byte("POST /users/v1/register HTTP/1.1\r\nHost: 127.0.0.1:3000\r\nContent-Type: application/json\r\nContent-Length: 37\r\n\r\n{\"username\":\"test\",\"password\":\"test\"}")))

	conversation := decodeSingleConversation(t, out.String())
	if conversation.Method != http.MethodPost {
		t.Fatalf("unexpected method: %s", conversation.Method)
	}
	if conversation.Path != "/users/v1/register" {
		t.Fatalf("unexpected path: %s", conversation.Path)
	}
	if conversation.RespStatus != "201 Created" {
		t.Fatalf("unexpected response status: %s", conversation.RespStatus)
	}
}

func TestProcessEventParsesCloseDelimitedResponseOnClose(t *testing.T) {
	var out bytes.Buffer
	cfg := testConfig(&out)
	store := newSessionStore(cfg.sessionTTL)
	stats := &workerStats{}

	processEvent(store, cfg, stats, testEvent(1, directionRead, []byte("GET / HTTP/1.1\r\nHost: 127.0.0.1:3000\r\n\r\n")))
	processEvent(store, cfg, stats, testEvent(2, directionWrite, []byte("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello")))
	if out.Len() != 0 {
		t.Fatalf("expected no output before close, got %q", out.String())
	}

	closeEvent := testEvent(3, directionWrite, nil)
	closeEvent.EventType = eventTypeClose
	processEvent(store, cfg, stats, closeEvent)

	conversation := decodeSingleConversation(t, out.String())
	if conversation.RespBody != "hello" {
		t.Fatalf("unexpected response body: %q", conversation.RespBody)
	}
	if atomic.LoadUint64(&stats.closedSessions) != 1 {
		t.Fatalf("unexpected closed session count: %d", stats.closedSessions)
	}
}

func testConfig(out *bytes.Buffer) config {
	return config{
		sessionTTL:     defaultSessionTTL,
		statsInterval:  defaultStatsInterval,
		maxBodyBytes:   defaultMaxBodyBytes,
		maxStreamBytes: defaultMaxStreamBytes,
		prettyOutput:   false,
		outputContract: "legacy",
		output:         out,
	}
}

func testEvent(seq uint32, direction uint8, payload []byte) ApiEvent {
	return ApiEvent{
		Timestamp:  uint64(seq),
		PID:        100,
		TID:        100,
		FD:         9,
		Generation: 1,
		Seq:        seq,
		ChunkIndex: 0,
		ChunkCount: 1,
		Direction:  direction,
		EventType:  eventTypeData,
		Size:       uint32(len(payload)),
		Payload:    payload,
	}
}

func TestProcessEventEmitsCleanNormalizedContract(t *testing.T) {
	var out bytes.Buffer
	cfg := testConfig(&out)
	cfg.outputContract = "normalized"
	store := newSessionStore(cfg.sessionTTL)
	stats := &workerStats{}

	processEvent(store, cfg, stats, testEvent(1, directionRead, []byte("GET /api HTTP/1.1\r\nHost: juice.local\r\n\r\n")))
	processEvent(store, cfg, stats, testEvent(2, directionWrite, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}")))

	var normalized NormalizedConversation
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &normalized); err != nil {
		t.Fatalf("failed to decode normalized output: %v\nraw=%s", err, out.String())
	}
	if normalized.HTTP.Request.Method != http.MethodGet || normalized.HTTP.Request.Path != "/api" {
		t.Fatalf("unexpected normalized request: %+v", normalized.HTTP.Request)
	}
	if normalized.HTTP.Response.Status != "200 OK" || normalized.HTTP.Response.Body != "{}" {
		t.Fatalf("unexpected normalized response: %+v", normalized.HTTP.Response)
	}
}

func TestProcessEventEmitsNormalizedMetadata(t *testing.T) {
	var out bytes.Buffer
	cfg := testConfig(&out)
	store := newSessionStore(cfg.sessionTTL)
	stats := &workerStats{}

	req := testEvent(1, directionRead, []byte("GET /api HTTP/1.1\r\nHost: juice.local\r\n\r\n"))
	req.CaptureSource = "ebpf"
	req.CaptureMode = "container"
	req.Connection = ConnectionMetadata{SrcIP: "10.0.0.2", SrcPort: 3000, DstIP: "10.0.0.1", DstPort: 52144, Protocol: "tcp", Family: "ipv4", Role: "inbound"}
	req.Process = ProcessMetadata{PID: 100, Name: "node", Exe: "/usr/local/bin/node"}
	req.Container = ContainerMetadata{ID: "abc123", Name: "juice-shop"}

	resp := testEvent(2, directionWrite, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"))
	resp.Connection = req.Connection
	resp.Process = req.Process
	resp.Container = req.Container

	processEvent(store, cfg, stats, req)
	processEvent(store, cfg, stats, resp)

	conversation := decodeSingleConversation(t, out.String())
	if conversation.SchemaVersion != "http.conversation.v1" {
		t.Fatalf("unexpected schema version: %s", conversation.SchemaVersion)
	}
	if conversation.CaptureSource != "ebpf" || conversation.CaptureMode != "container" {
		t.Fatalf("unexpected capture metadata: source=%s mode=%s", conversation.CaptureSource, conversation.CaptureMode)
	}
	if conversation.Connection.SrcIP != "10.0.0.2" || conversation.Connection.DstPort != 52144 {
		t.Fatalf("unexpected connection metadata: %+v", conversation.Connection)
	}
	if conversation.Process.Name != "node" || conversation.Container.ID != "abc123" {
		t.Fatalf("unexpected process/container metadata: proc=%+v container=%+v", conversation.Process, conversation.Container)
	}
	if conversation.Request.Body != conversation.ReqBody || conversation.Response.Status != conversation.RespStatus {
		t.Fatalf("nested request/response fields are not aligned with compatibility fields")
	}
}

func TestProcessEventPropagatesLossMetadata(t *testing.T) {
	var out bytes.Buffer
	cfg := testConfig(&out)
	store := newSessionStore(cfg.sessionTTL)
	stats := &workerStats{}

	req := testEvent(1, directionRead, []byte("GET /large HTTP/1.1\r\nHost: api.local\r\n\r\n"))
	req.Loss = LossMetadata{Truncated: true, OriginalSize: 8192, CapturedSize: 4096, Reason: "payload_exceeded_agent_struct_size"}
	resp := testEvent(3, directionWrite, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"))

	processEvent(store, cfg, stats, req)
	processEvent(store, cfg, stats, resp)

	conversation := decodeSingleConversation(t, out.String())
	if !conversation.Loss.Truncated {
		t.Fatalf("expected truncation metadata")
	}
	if !conversation.Loss.SequenceGap || conversation.Loss.ExpectedNextSeq != 2 || conversation.Loss.ActualSeq != 3 {
		t.Fatalf("unexpected sequence gap metadata: %+v", conversation.Loss)
	}
}

func decodeSingleConversation(t *testing.T, raw string) HttpConversation {
	t.Helper()
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		t.Fatalf("expected conversation output")
	}

	var conversation HttpConversation
	if err := json.Unmarshal([]byte(trimmed), &conversation); err != nil {
		t.Fatalf("failed to decode conversation JSON: %v\nraw=%s", err, raw)
	}
	return conversation
}
