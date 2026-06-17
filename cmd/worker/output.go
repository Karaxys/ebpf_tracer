package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

func emitConversation(cfg config, parsedReq parsedRequest, resp *http.Response, respBody string) {
	out := cfg.output
	if out == nil {
		out = os.Stdout
	}

	host := parsedReq.req.Host
	if host == "" {
		host = parsedReq.req.Header.Get("Host")
	}

	path := parsedReq.req.URL.RequestURI()
	if path == "" {
		path = parsedReq.req.URL.Path
	}

	prettyReqBody := prettyMaybeJSON(parsedReq.body)
	prettyRespBody := prettyMaybeJSON(respBody)
	url := fmt.Sprintf("http://%s%s", host, path)
	statusCode := resp.StatusCode
	normalized := NormalizedConversation{
		ID:            OIDField{OID: newOID()},
		SchemaVersion: "http.conversation.v1",
		AgentID:       cfg.agentID,
		CaptureSource: firstNonEmpty(parsedReq.captureSource, "ebpf"),
		CaptureMode:   parsedReq.captureMode,
		CapturedAt:    DateField{Date: parsedReq.capturedAt.Format(time.RFC3339Nano)},
		Connection:    parsedReq.connection,
		Process:       parsedReq.process,
		Container:     parsedReq.container,
		Loss:          parsedReq.loss,
		HTTP: HTTPExchange{
			Request: NormalizedHTTPRequest{
				Method:  parsedReq.req.Method,
				URL:     url,
				Host:    host,
				Path:    path,
				Headers: parsedReq.req.Header,
				Body:    prettyReqBody,
			},
			Response: NormalizedHTTPResponse{
				Status:     resp.Status,
				StatusCode: &statusCode,
				Headers:    resp.Header,
				Body:       prettyRespBody,
			},
		},
	}

	legacy := HttpConversation{
		ID:            normalized.ID,
		SchemaVersion: normalized.SchemaVersion,
		CaptureSource: normalized.CaptureSource,
		CaptureMode:   normalized.CaptureMode,
		CreatedAt:     DateField{Date: parsedReq.capturedAt.Format(time.RFC3339Nano)},
		Connection:    parsedReq.connection,
		Process:       parsedReq.process,
		Container:     parsedReq.container,
		Loss:          parsedReq.loss,
		Request:       HttpMessage{Headers: parsedReq.req.Header, Body: prettyReqBody},
		Response:      HttpMessage{Headers: resp.Header, Body: prettyRespBody, Status: resp.Status},
		Method:        parsedReq.req.Method,
		URL:           url,
		Host:          host,
		Path:          path,
		ReqHeaders:    parsedReq.req.Header,
		ReqBody:       prettyReqBody,
		RespStatus:    resp.Status,
		RespBody:      prettyRespBody,
	}

	payload := any(normalized)
	if cfg.outputContract == "legacy" {
		payload = legacy
	} else if cfg.outputContract == "both" {
		payload = struct {
			Normalized NormalizedConversation `json:"normalized"`
			Legacy     HttpConversation       `json:"legacy"`
		}{Normalized: normalized, Legacy: legacy}
	}

	var output []byte
	var err error
	if cfg.sink != nil {
		output, err = json.Marshal(payload)
	} else if cfg.prettyOutput {
		output, err = json.MarshalIndent(payload, "", "  ")
	} else {
		output, err = json.Marshal(payload)
	}

	if err != nil {
		log.Printf("Failed to marshal conversation: %v", err)
		return
	}

	if cfg.sink != nil {
		if err := cfg.sink.Emit(output); err != nil {
			log.Printf("Failed to emit conversation to %s sink: %v", cfg.outputSink, err)
		}
		return
	}

	title := fmt.Sprintf("%s %s -> %s", normalized.HTTP.Request.Method, normalized.HTTP.Request.Path, normalized.HTTP.Response.Status)
	if cfg.prettyOutput {
		bar := strings.Repeat("=", boundedLen(len(title)+20, 64, 120))
		fmt.Fprintln(out, bar)
		fmt.Fprintf(out, " TRAFFIC %s\n", title)
		fmt.Fprintln(out, bar)
	}

	fmt.Fprintln(out, string(output))
	if cfg.prettyOutput {
		fmt.Fprintln(out, strings.Repeat("-", 96))
	}
}

func runSessionCleanup(store *sessionStore, cfg config, stats *workerStats, stop <-chan struct{}) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			removed, parsed := store.cleanupExpired(time.Now().Add(-cfg.sessionTTL), func(state *StreamState) int {
				state.mu.Lock()
				defer state.mu.Unlock()
				return drainParsedConversations(cfg, stats, state, true)
			})
			if removed > 0 {
				atomic.AddUint64(&stats.expiredSessions, uint64(removed))
			}
			if parsed > 0 {
				atomic.AddUint64(&stats.parsed, uint64(parsed))
			}
		}
	}
}

func runStatsReporter(cfg config, stats *workerStats, stop <-chan struct{}) {
	ticker := time.NewTicker(cfg.statsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			logStats("periodic", stats)
		}
	}
}

func logStats(prefix string, stats *workerStats) {
	log.Printf(
		"stats[%s] received=%d decoded=%d parsed=%d closed=%d malformed=%d noise=%d outOfOrder=%d routedReq=%d routedResp=%d routedUnknown=%d reqParsed=%d respParsed=%d reqPending=%d respPending=%d noReqStart=%d noRespStart=%d reqOverflow=%d respOverflow=%d kafkaErrors=%d expiredSessions=%d",
		prefix,
		atomic.LoadUint64(&stats.received),
		atomic.LoadUint64(&stats.decoded),
		atomic.LoadUint64(&stats.parsed),
		atomic.LoadUint64(&stats.closedSessions),
		atomic.LoadUint64(&stats.droppedMalformed),
		atomic.LoadUint64(&stats.droppedNoise),
		atomic.LoadUint64(&stats.outOfOrder),
		atomic.LoadUint64(&stats.routedReq),
		atomic.LoadUint64(&stats.routedResp),
		atomic.LoadUint64(&stats.routedUnknown),
		atomic.LoadUint64(&stats.requestParsed),
		atomic.LoadUint64(&stats.responseParsed),
		atomic.LoadUint64(&stats.requestParsePending),
		atomic.LoadUint64(&stats.responseParsePending),
		atomic.LoadUint64(&stats.droppedNoReqStart),
		atomic.LoadUint64(&stats.droppedNoRespInit),
		atomic.LoadUint64(&stats.droppedReqOverflow),
		atomic.LoadUint64(&stats.droppedRespOverflow),
		atomic.LoadUint64(&stats.kafkaErrors),
		atomic.LoadUint64(&stats.expiredSessions),
	)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func prettyMaybeJSON(body string) string {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return body
	}

	first := trimmed[0]
	if first != '{' && first != '[' {
		return body
	}

	var pretty bytes.Buffer
	if err := json.Indent(&pretty, []byte(trimmed), "", "  "); err != nil {
		return body
	}

	return pretty.String()
}

func isCounterNoise(payload []byte) bool {
	if len(payload) != 8 {
		return false
	}

	if payload[0] != 1 && payload[0] != 2 {
		return false
	}

	for i := 1; i < 8; i++ {
		if payload[i] != 0 {
			return false
		}
	}

	return true
}

func boundedLen(n, min, max int) int {
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

func newOID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%024x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func directionName(direction uint8) string {
	switch direction {
	case directionRead:
		return "read"
	case directionWrite:
		return "write"
	default:
		return fmt.Sprintf("unknown(%d)", direction)
	}
}

func routeName(request bool) string {
	if request {
		return "request"
	}
	return "response"
}

func payloadPreview(payload []byte, max int) string {
	if len(payload) == 0 || max <= 0 {
		return ""
	}
	if len(payload) > max {
		payload = payload[:max]
	}
	return strings.ToValidUTF8(string(payload), ".")
}
