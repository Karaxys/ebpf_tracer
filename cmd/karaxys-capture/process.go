package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

func sessionKey(event CaptureEvent) string {
	if event.CaptureSource == "ebpf" && event.PID != 0 && event.FD != 0 {
		return fmt.Sprintf("pidfd:%d-%d-%d", event.PID, event.FD, event.Generation)
	}
	if event.Connection.Protocol != "" && event.Connection.SrcIP != "" && event.Connection.DstIP != "" {
		return fmt.Sprintf("conn:%s:%s:%d-%s:%d:%d",
			event.Connection.Protocol,
			event.Connection.SrcIP, event.Connection.SrcPort,
			event.Connection.DstIP, event.Connection.DstPort,
			event.Generation,
		)
	}
	return fmt.Sprintf("pidfd:%d-%d-%d", event.PID, event.FD, event.Generation)
}

func processEvent(store *sessionStore, cfg config, stats *processingStats, event CaptureEvent) {
	if event.EventType == eventTypeClose {
		handleCloseEvent(store, cfg, stats, event)
		return
	}
	if event.EventType != eventTypeData {
		atomic.AddUint64(&stats.droppedMalformed, 1)
		return
	}
	if event.Size == 0 || len(event.Payload) == 0 {
		atomic.AddUint64(&stats.droppedNoise, 1)
		return
	}

	payloadSize := int(event.Size)
	if payloadSize > len(event.Payload) {
		payloadSize = len(event.Payload)
	}
	payload := event.Payload[:payloadSize]
	if isCounterNoise(payload) {
		atomic.AddUint64(&stats.droppedNoise, 1)
		return
	}

	key := sessionKey(event)
	state := store.getOrCreate(key)

	state.mu.Lock()
	defer state.mu.Unlock()

	state.LastActive = time.Now()
	mergeStreamMetadata(state, event)

	// For TLS connections the same fd yields both ciphertext (syscall hooks) and
	// plaintext (SSL uprobes). Once plaintext is seen, drop the ciphertext already
	// buffered and ignore further non-SSL events on this stream.
	isSSL := event.Flags&eventFlagSSL != 0
	if isSSL && !state.Ssl {
		state.ReqData = nil
		state.RespData = nil
		state.PendingReqs = nil
		state.Ssl = true
		state.H2 = false
		state.H2Emitted = nil
	}
	if state.Ssl != isSSL {
		return
	}

	if state.HasLastSeq && event.Seq > state.LastSeq+1 {
		atomic.AddUint64(&stats.outOfOrder, 1)
		state.Loss.SequenceGap = true
		state.Loss.ExpectedNextSeq = state.LastSeq + 1
		state.Loss.ActualSeq = event.Seq
	}
	if event.Loss.Truncated {
		state.Loss.Truncated = true
		state.Loss.OriginalSize = event.Loss.OriginalSize
		state.Loss.CapturedSize = event.Loss.CapturedSize
		state.Loss.Reason = event.Loss.Reason
	}
	if !state.HasLastSeq || event.Seq >= state.LastSeq {
		state.LastSeq = event.Seq
		state.HasLastSeq = true
	}

	routeAsRequest := event.Direction == directionRead
	payloadKind := classifyPayload(payload)
	switch payloadKind {
	case payloadRequest:
		routeAsRequest = true
	case payloadResponse:
		routeAsRequest = false
	case payloadUnknown:
		atomic.AddUint64(&stats.routedUnknown, 1)
	}

	if routeAsRequest {
		atomic.AddUint64(&stats.routedReq, 1)
		state.ReqData = append(state.ReqData, payload...)
		if len(state.ReqData) > cfg.maxStreamBytes {
			state.ReqData = nil
			state.PendingReqs = nil
			atomic.AddUint64(&stats.droppedReqOverflow, 1)
			return
		}
	} else {
		atomic.AddUint64(&stats.routedResp, 1)
		state.RespData = append(state.RespData, payload...)
		if len(state.RespData) > cfg.maxStreamBytes {
			state.RespData = nil
			state.PendingReqs = nil
			atomic.AddUint64(&stats.droppedRespOverflow, 1)
			return
		}
	}

	if !state.H2 {
		if bytes.HasPrefix(state.ReqData, h2Preface) || bytes.HasPrefix(state.RespData, h2Preface) {
			state.H2 = true
		}
	}

	if cfg.debugPayload {
		log.Printf(
			"event pid=%d fd=%d gen=%d seq=%d dir=%d ssl=%t h2=%t kind=%s size=%d req_buf=%d resp_buf=%d pending=%d preview=%q",
			event.PID, event.FD, event.Generation, event.Seq, event.Direction, isSSL, state.H2,
			payloadKind.String(), len(payload),
			len(state.ReqData), len(state.RespData), len(state.PendingReqs),
			payloadPreview(payload, 96),
		)
	}

	parsed := drainStream(cfg, stats, state, false)
	if parsed > 0 {
		atomic.AddUint64(&stats.parsed, uint64(parsed))
	}
}

func drainStream(cfg config, stats *processingStats, state *StreamState, allowCloseDelimited bool) int {
	if state.H2 {
		return drainH2(cfg, stats, state)
	}
	// Hold off until a partial preface match is resolved either way — the
	// HTTP/1 sync-probe-window below would otherwise prune it before the
	// full match completes if it arrives split across events.
	if isH2PrefaceCandidate(state.ReqData) {
		return 0
	}
	return drainParsedConversations(cfg, stats, state, allowCloseDelimited)
}

func isH2PrefaceCandidate(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if len(data) >= len(h2Preface) {
		return bytes.Equal(data[:len(h2Preface)], h2Preface)
	}
	return bytes.Equal(data, h2Preface[:len(data)])
}

func handleCloseEvent(store *sessionStore, cfg config, stats *processingStats, event CaptureEvent) {
	key := sessionKey(event)
	state, ok := store.get(key)
	if !ok {
		return
	}

	state.mu.Lock()
	parsed := drainStream(cfg, stats, state, true)
	state.mu.Unlock()

	if parsed > 0 {
		atomic.AddUint64(&stats.parsed, uint64(parsed))
	}

	store.remove(key)
	atomic.AddUint64(&stats.closedSessions, 1)
}

func mergeStreamMetadata(state *StreamState, event CaptureEvent) {
	if state.CaptureSource == "" {
		state.CaptureSource = event.CaptureSource
	}
	if state.CaptureMode == "" {
		state.CaptureMode = event.CaptureMode
	}
	if state.Connection.Protocol == "" {
		state.Connection = event.Connection
	}
	if state.Process.PID == 0 {
		state.Process = event.Process
	}
	if state.Container.ID == "" {
		state.Container = event.Container
	}
}

func classifyPayload(chunk []byte) payloadKind {
	reqIdx := earliestMethodIndex(chunk)
	respIdx := bytes.Index(chunk, []byte("HTTP/1."))

	if reqIdx >= 0 && (respIdx < 0 || reqIdx < respIdx) {
		return payloadRequest
	}
	if respIdx >= 0 {
		return payloadResponse
	}
	return payloadUnknown
}

var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("PATCH "),
	[]byte("DELETE "), []byte("HEAD "), []byte("OPTIONS "), []byte("TRACE "),
	[]byte("CONNECT "),
}

func earliestMethodIndex(chunk []byte) int {
	best := -1
	for _, method := range httpMethods {
		idx := bytes.Index(chunk, method)
		if idx >= 0 && (best == -1 || idx < best) {
			best = idx
		}
	}
	return best
}

func syncRequestBuffer(data []byte) ([]byte, int) {
	if len(data) == 0 {
		return data, 0
	}
	idx := earliestMethodIndex(data)
	if idx > 0 {
		return data[idx:], idx
	}
	if idx == -1 && len(data) > requestStartProbeWindow {
		dropped := len(data) - requestStartProbeWindow
		return data[dropped:], dropped
	}
	return data, 0
}

func syncResponseBuffer(data []byte) ([]byte, int) {
	if len(data) == 0 {
		return data, 0
	}
	idx := bytes.Index(data, []byte("HTTP/1."))
	if idx > 0 {
		return data[idx:], idx
	}
	if idx == -1 && len(data) > responseStartProbeWindow {
		dropped := len(data) - responseStartProbeWindow
		return data[dropped:], dropped
	}
	return data, 0
}

func drainParsedConversations(cfg config, stats *processingStats, state *StreamState, allowCloseDelimited bool) int {
	parsedCount := 0

	for {
		var trimmed int
		state.ReqData, trimmed = syncRequestBuffer(state.ReqData)
		if trimmed > 0 {
			atomic.AddUint64(&stats.droppedNoReqStart, uint64(trimmed))
		}

		req, reqBody, consumed, ok := parseOneRequest(state.ReqData, cfg.maxBodyBytes)
		if !ok {
			if len(state.ReqData) > 0 {
				atomic.AddUint64(&stats.requestParsePending, 1)
			}
			break
		}
		atomic.AddUint64(&stats.requestParsed, 1)
		state.PendingReqs = append(state.PendingReqs, parsedRequest{
			req:           req,
			body:          reqBody,
			capturedAt:    time.Now().UTC(),
			captureSource: state.CaptureSource,
			captureMode:   state.CaptureMode,
			connection:    state.Connection,
			process:       state.Process,
			container:     state.Container,
			loss:          state.Loss,
		})
		state.ReqData = state.ReqData[consumed:]
	}

	for len(state.PendingReqs) > 0 {
		var trimmed int
		state.RespData, trimmed = syncResponseBuffer(state.RespData)
		if trimmed > 0 {
			atomic.AddUint64(&stats.droppedNoRespInit, uint64(trimmed))
		}

		resp, respBody, consumed, ok := parseOneResponse(state.RespData, state.PendingReqs[0].req, cfg.maxBodyBytes, allowCloseDelimited)
		if !ok {
			if len(state.RespData) > 0 {
				atomic.AddUint64(&stats.responseParsePending, 1)
			}
			break
		}
		atomic.AddUint64(&stats.responseParsed, 1)
		parsedReq := state.PendingReqs[0]
		parsedReq.loss = mergeLossMetadata(parsedReq.loss, state.Loss)
		if err := emitConversation(cfg, parsedReq, resp, respBody); err != nil {
			atomic.AddUint64(&stats.emitErrors, 1)
			log.Printf("emit error (req=%s %s): %v", parsedReq.req.Method, parsedReq.req.URL.RequestURI(), err)
		}
		parsedCount++
		state.PendingReqs = state.PendingReqs[1:]
		state.RespData = state.RespData[consumed:]
	}

	return parsedCount
}

func mergeLossMetadata(base, latest LossMetadata) LossMetadata {
	if latest.Truncated {
		base.Truncated = true
		base.OriginalSize = latest.OriginalSize
		base.CapturedSize = latest.CapturedSize
		base.Reason = latest.Reason
	}
	if latest.SequenceGap {
		base.SequenceGap = true
		base.ExpectedNextSeq = latest.ExpectedNextSeq
		base.ActualSeq = latest.ActualSeq
	}
	return base
}

func parseOneRequest(data []byte, maxBodyBytes int64) (*http.Request, string, int, bool) {
	if len(data) == 0 {
		return nil, "", 0, false
	}
	source := bytes.NewReader(data)
	reader := bufio.NewReader(source)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, "", 0, false
	}
	body, complete := readBodyStringComplete(req.Body, maxBodyBytes)
	if !complete {
		return nil, "", 0, false
	}
	consumed := len(data) - (source.Len() + reader.Buffered())
	if consumed <= 0 {
		return nil, "", 0, false
	}
	return req, body, consumed, true
}

func parseOneResponse(data []byte, req *http.Request, maxBodyBytes int64, allowCloseDelimited bool) (*http.Response, string, int, bool) {
	if len(data) == 0 {
		return nil, "", 0, false
	}
	source := bytes.NewReader(data)
	reader := bufio.NewReader(source)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, "", 0, false
	}
	if !allowCloseDelimited && responseNeedsConnectionCloseBoundary(req, resp) {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil, "", 0, false
	}
	body, complete := readBodyStringComplete(resp.Body, maxBodyBytes)
	if !complete {
		return nil, "", 0, false
	}
	consumed := len(data) - (source.Len() + reader.Buffered())
	if consumed <= 0 {
		return nil, "", 0, false
	}
	return resp, body, consumed, true
}

func responseNeedsConnectionCloseBoundary(req *http.Request, resp *http.Response) bool {
	if resp == nil || responseHasNoBody(req, resp) || resp.ContentLength >= 0 {
		return false
	}
	return !hasChunkedTransfer(resp.TransferEncoding)
}

func responseHasNoBody(req *http.Request, resp *http.Response) bool {
	if req != nil && strings.EqualFold(req.Method, http.MethodHead) {
		return true
	}
	if resp == nil {
		return true
	}
	if resp.StatusCode >= 100 && resp.StatusCode < 200 {
		return true
	}
	return resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified
}

func hasChunkedTransfer(te []string) bool {
	for _, enc := range te {
		if strings.EqualFold(strings.TrimSpace(enc), "chunked") {
			return true
		}
	}
	return false
}

func readBodyStringComplete(body io.ReadCloser, maxBodyBytes int64) (string, bool) {
	if body == nil {
		return "", true
	}
	defer body.Close()

	limited := io.LimitReader(body, maxBodyBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return "", false
		}
		return "", false
	}

	truncated := false
	if int64(len(data)) > maxBodyBytes {
		data = data[:int(maxBodyBytes)]
		truncated = true
	}

	if utf8.Valid(data) {
		text := prettyMaybeJSON(string(data))
		if truncated {
			return text + "\n[truncated]", true
		}
		return text, true
	}

	encoded := "base64:" + base64.StdEncoding.EncodeToString(data)
	if truncated {
		return encoded + "\n[truncated]", true
	}
	return encoded, true
}
