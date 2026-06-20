package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

func TestSessionKeyUsesPIDFDForEBPFEvenWithConnectionMetadata(t *testing.T) {
	event := ApiEvent{
		CaptureSource: "ebpf",
		PID:           19389,
		FD:            5,
		Generation:    81,
		Connection: ConnectionMetadata{
			SrcIP:    "172.17.0.2",
			SrcPort:  5000,
			DstIP:    "172.17.0.1",
			DstPort:  49140,
			Protocol: "tcp",
			Family:   "ipv4",
			Role:     "outbound",
		},
	}

	if got, want := sessionKey(event), "pidfd:19389-5-81"; got != want {
		t.Fatalf("sessionKey() = %q, want %q", got, want)
	}
}

func TestSessionKeyUsesConnectionForNonEBPFEvents(t *testing.T) {
	event := ApiEvent{
		CaptureSource: "proxy",
		PID:           19389,
		FD:            5,
		Generation:    81,
		Connection: ConnectionMetadata{
			SrcIP:    "10.0.0.10",
			SrcPort:  51512,
			DstIP:    "10.0.0.20",
			DstPort:  8080,
			Protocol: "tcp",
		},
	}

	if got, want := sessionKey(event), "conn:tcp:10.0.0.10:51512-10.0.0.20:8080:81"; got != want {
		t.Fatalf("sessionKey() = %q, want %q", got, want)
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

func TestProcessEventHTTPSinkPostsNormalizedConversation(t *testing.T) {
	var received []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if r.URL.Path != "/v1/ingest/conversations" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer agent-token" {
			t.Errorf("missing bearer token")
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected content type: %s", r.Header.Get("Content-Type"))
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		received = body
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cfg := testConfig(&bytes.Buffer{})
	cfg.outputSink = outputSinkHTTP
	cfg.outputContract = "normalized"
	cfg.backendURL = server.URL
	cfg.agentToken = "agent-token"
	cfg.agentID = "agent-linux-01"
	cfg.httpTimeout = time.Second
	cfg.httpMaxRetries = 0
	sink, err := newConversationSink(cfg)
	if err != nil {
		t.Fatalf("create sink: %v", err)
	}
	cfg.sink = sink
	defer sink.Close()

	store := newSessionStore(cfg.sessionTTL)
	stats := &workerStats{}
	processEvent(store, cfg, stats, testEvent(1, directionRead, []byte("GET /api HTTP/1.1\r\nHost: juice.local\r\n\r\n")))
	processEvent(store, cfg, stats, testEvent(2, directionWrite, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}")))

	if len(received) == 0 {
		t.Fatal("expected backend to receive conversation")
	}
	var normalized NormalizedConversation
	if err := json.Unmarshal(received, &normalized); err != nil {
		t.Fatalf("decode posted conversation: %v\nraw=%s", err, string(received))
	}
	if normalized.AgentID != "agent-linux-01" || normalized.CaptureSource != "ebpf" {
		t.Fatalf("unexpected metadata: %+v", normalized)
	}
	if normalized.HTTP.Response.StatusCode == nil || *normalized.HTTP.Response.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %+v", normalized.HTTP.Response.StatusCode)
	}
}

func TestHTTPSinkRetriesBackendFailures(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) == 1 {
			http.Error(w, "temporary failure", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	deadLetter := filepath.Join(t.TempDir(), "deadletters.jsonl")
	sink, err := newConversationSink(config{
		outputSink:      outputSinkHTTP,
		backendURL:      server.URL,
		agentToken:      "agent-token",
		httpTimeout:     time.Second,
		httpMaxRetries:  1,
		httpRetryDelay:  time.Millisecond,
		deadLetterFile:  deadLetter,
		outputContract:  "normalized",
		outputBootstrap: defaultBootstrap,
	})
	if err != nil {
		t.Fatalf("create sink: %v", err)
	}
	defer sink.Close()

	if err := sink.Emit([]byte(`{"schema_version":"http.conversation.v1"}`)); err != nil {
		t.Fatalf("expected retry to recover: %v", err)
	}
	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Fatalf("unexpected attempts: %d", got)
	}
	if _, err := os.Stat(deadLetter); !os.IsNotExist(err) {
		t.Fatalf("expected no dead-letter file, stat err=%v", err)
	}
}

func TestHTTPSinkWritesDeadLetterAfterFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer server.Close()

	deadLetter := filepath.Join(t.TempDir(), "deadletters.jsonl")
	sink, err := newConversationSink(config{
		outputSink:      outputSinkHTTP,
		backendURL:      server.URL,
		agentToken:      "agent-token",
		httpTimeout:     time.Second,
		httpMaxRetries:  0,
		httpRetryDelay:  time.Millisecond,
		deadLetterFile:  deadLetter,
		outputContract:  "normalized",
		outputBootstrap: defaultBootstrap,
	})
	if err != nil {
		t.Fatalf("create sink: %v", err)
	}
	defer sink.Close()

	payload := []byte(`{"schema_version":"http.conversation.v1"}`)
	if err := sink.Emit(payload); err == nil {
		t.Fatal("expected sink emit failure")
	}

	raw, err := os.ReadFile(deadLetter)
	if err != nil {
		t.Fatalf("read dead letter: %v", err)
	}
	var record sinkDeadLetter
	if err := json.Unmarshal(bytes.TrimSpace(raw), &record); err != nil {
		t.Fatalf("decode dead letter: %v\nraw=%s", err, string(raw))
	}
	if record.Sink != outputSinkHTTP || !bytes.Equal(record.Payload, payload) {
		t.Fatalf("unexpected dead letter: %+v", record)
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
	resp.CaptureSource = req.CaptureSource
	resp.CaptureMode = req.CaptureMode
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

func TestProcessEventPropagatesLongPayloadChunkTruncation(t *testing.T) {
	var out bytes.Buffer
	cfg := testConfig(&out)
	store := newSessionStore(cfg.sessionTTL)
	stats := &workerStats{}

	req := testEvent(1, directionRead, []byte("POST /large HTTP/1.1\r\nHost: api.local\r\nContent-Length: 5\r\n\r\nhello"))
	req.Loss = LossMetadata{Truncated: true, OriginalSize: 20000, CapturedSize: 16384, Reason: "payload_exceeded_agent_capture_limit"}
	resp := testEvent(2, directionWrite, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"))

	processEvent(store, cfg, stats, req)
	processEvent(store, cfg, stats, resp)

	conversation := decodeSingleConversation(t, out.String())
	if !conversation.Loss.Truncated {
		t.Fatalf("expected long payload truncation metadata")
	}
	if conversation.Loss.OriginalSize != 20000 || conversation.Loss.CapturedSize != 16384 {
		t.Fatalf("unexpected truncation metadata: %+v", conversation.Loss)
	}
}

func TestProcessEventDetectsSequenceGapAfterFirstZeroSeq(t *testing.T) {
	var out bytes.Buffer
	cfg := testConfig(&out)
	store := newSessionStore(cfg.sessionTTL)
	stats := &workerStats{}

	req := testEvent(0, directionRead, []byte("GET /zero HTTP/1.1\r\nHost: api.local\r\n\r\n"))
	resp := testEvent(2, directionWrite, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"))

	processEvent(store, cfg, stats, req)
	processEvent(store, cfg, stats, resp)

	conversation := decodeSingleConversation(t, out.String())
	if !conversation.Loss.SequenceGap {
		t.Fatalf("expected sequence gap after seq 0 to seq 2")
	}
	if conversation.Loss.ExpectedNextSeq != 1 || conversation.Loss.ActualSeq != 2 {
		t.Fatalf("unexpected sequence gap metadata: %+v", conversation.Loss)
	}
}

func TestProcessEventHandlesInterleavedRequestsAndResponses(t *testing.T) {
	var out bytes.Buffer
	cfg := testConfig(&out)
	store := newSessionStore(cfg.sessionTTL)
	stats := &workerStats{}

	processEvent(store, cfg, stats, testEvent(1, directionRead, []byte("GET /one HTTP/1.1\r\nHost: api.local\r\n\r\n")))
	processEvent(store, cfg, stats, testEvent(2, directionRead, []byte("GET /two HTTP/1.1\r\nHost: api.local\r\n\r\n")))
	processEvent(store, cfg, stats, testEvent(3, directionWrite, []byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none")))
	processEvent(store, cfg, stats, testEvent(4, directionWrite, []byte("HTTP/1.1 201 Created\r\nContent-Length: 3\r\n\r\ntwo")))

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected two conversations, got %d raw=%q", len(lines), out.String())
	}
	var first, second HttpConversation
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("decode first conversation: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("decode second conversation: %v", err)
	}
	if first.Path != "/one" || first.RespStatus != "200 OK" {
		t.Fatalf("unexpected first conversation: %+v", first)
	}
	if second.Path != "/two" || second.RespStatus != "201 Created" {
		t.Fatalf("unexpected second conversation: %+v", second)
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
