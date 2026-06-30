package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
)

// Kernel drop_metrics array indices — must match the DROP_* enum in tracer.bpf.c.
const (
	dropRingbufReserve = 0
	dropCopyWrite      = 1
	dropCopyRead       = 2
	dropIovRead        = 3
	dropMissingContext = 4
	dropNoise          = 5
	dropFDFilter       = 6
	dropDirection      = 7
	dropPortFilter     = 8
	dropCgroupFilter   = 9
)

func readDropMetric(dropMap *ebpf.Map, idx uint32) uint64 {
	var value uint64
	if err := dropMap.Lookup(&idx, &value); err != nil {
		return 0
	}
	return value
}

// logKernelDrops surfaces the in-kernel drop counters. ringbuf_reserve > 0 means
// the events ring buffer overflowed and the kernel discarded events before the
// userspace reader ever saw them — the classic symptom of an all-pids firehose.
func logKernelDrops(dropMap *ebpf.Map) {
	if dropMap == nil {
		return
	}
	log.Printf(
		"kernel_drops ringbuf_reserve=%d copy_write=%d copy_read=%d iov_read=%d missing_ctx=%d noise=%d fd_filter=%d direction=%d port_filter=%d cgroup_filter=%d",
		readDropMetric(dropMap, dropRingbufReserve),
		readDropMetric(dropMap, dropCopyWrite),
		readDropMetric(dropMap, dropCopyRead),
		readDropMetric(dropMap, dropIovRead),
		readDropMetric(dropMap, dropMissingContext),
		readDropMetric(dropMap, dropNoise),
		readDropMetric(dropMap, dropFDFilter),
		readDropMetric(dropMap, dropDirection),
		readDropMetric(dropMap, dropPortFilter),
		readDropMetric(dropMap, dropCgroupFilter),
	)
}

func emitConversation(cfg config, parsedReq parsedRequest, resp *http.Response, respBody string) error {
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

	payload, err := json.Marshal(normalized)
	if err != nil {
		log.Printf("Failed to marshal conversation: %v", err)
		return err
	}

	if cfg.sink != nil {
		return cfg.sink.Emit(payload)
	}

	// Fallback: write to stdout (test/debug only)
	out := cfg.output
	if out == nil {
		return fmt.Errorf("no sink configured")
	}
	fmt.Fprintln(out, string(payload))
	return nil
}

func runSessionCleanup(store *sessionStore, cfg config, stats *processingStats, stop <-chan struct{}) {
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

func runProcessingStats(stats *processingStats, interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			logProcessingStats("periodic", stats)
		}
	}
}

func logProcessingStats(prefix string, stats *processingStats) {
	log.Printf(
		"proc_stats[%s] received=%d parsed=%d closed=%d malformed=%d noise=%d outOfOrder=%d routedReq=%d routedResp=%d routedUnknown=%d reqParsed=%d respParsed=%d reqPending=%d respPending=%d noReqStart=%d noRespStart=%d reqOverflow=%d respOverflow=%d expiredSessions=%d emitErrors=%d",
		prefix,
		atomic.LoadUint64(&stats.received),
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
		atomic.LoadUint64(&stats.expiredSessions),
		atomic.LoadUint64(&stats.emitErrors),
	)
}

func logCaptureStats(prefix string, stats *captureStats) {
	log.Printf(
		"capture_stats[%s] ring_records=%d decoded=%d decode_errors=%d data=%d close=%d socket=%d skipped_noise=%d skipped_fd=%d truncated=%d bytes_captured=%d metadata_cache_hits=%d metadata_proc_hits=%d metadata_proc_misses=%d metadata_misses=%d kernel_tuple_fallbacks=%d channel_dropped=%d ring_read_errors=%d",
		prefix,
		atomic.LoadUint64(&stats.ringRecords),
		atomic.LoadUint64(&stats.decodedEvents),
		atomic.LoadUint64(&stats.decodeErrors),
		atomic.LoadUint64(&stats.dataEvents),
		atomic.LoadUint64(&stats.closeEvents),
		atomic.LoadUint64(&stats.socketEvents),
		atomic.LoadUint64(&stats.skippedNoise),
		atomic.LoadUint64(&stats.skippedFDFilter),
		atomic.LoadUint64(&stats.truncatedEvents),
		atomic.LoadUint64(&stats.bytesCaptured),
		atomic.LoadUint64(&stats.metadataCacheHits),
		atomic.LoadUint64(&stats.metadataProcHits),
		atomic.LoadUint64(&stats.metadataProcMisses),
		atomic.LoadUint64(&stats.metadataMisses),
		atomic.LoadUint64(&stats.kernelTupleFallbacks),
		atomic.LoadUint64(&stats.channelDropped),
		atomic.LoadUint64(&stats.ringReadErrors),
	)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func newOID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%024x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
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

func payloadPreview(payload []byte, max int) string {
	if len(payload) == 0 || max <= 0 {
		return ""
	}
	if len(payload) > max {
		payload = payload[:max]
	}
	return strings.ToValidUTF8(string(payload), ".")
}
