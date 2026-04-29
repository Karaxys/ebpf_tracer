package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
)

type healthSnapshot struct {
	Status          string `json:"status"`
	LocalQueueDepth int    `json:"local_queue_depth"`
}

func startHealthServer(addr string, stats *agentStats, producer *queuedProducer) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, healthSnapshot{Status: "ok", LocalQueueDepth: producer.depth()})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if producer.depth() >= cap(producer.queue) {
			w.WriteHeader(http.StatusServiceUnavailable)
			writeJSON(w, healthSnapshot{Status: "degraded", LocalQueueDepth: producer.depth()})
			return
		}
		writeJSON(w, healthSnapshot{Status: "ready", LocalQueueDepth: producer.depth()})
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "ebpf_tracer_ring_records %d\n", atomic.LoadUint64(&stats.ringRecords))
		fmt.Fprintf(w, "ebpf_tracer_decoded_events %d\n", atomic.LoadUint64(&stats.decodedEvents))
		fmt.Fprintf(w, "ebpf_tracer_decode_errors %d\n", atomic.LoadUint64(&stats.decodeErrors))
		fmt.Fprintf(w, "ebpf_tracer_data_events %d\n", atomic.LoadUint64(&stats.dataEvents))
		fmt.Fprintf(w, "ebpf_tracer_close_events %d\n", atomic.LoadUint64(&stats.closeEvents))
		fmt.Fprintf(w, "ebpf_tracer_skipped_noise %d\n", atomic.LoadUint64(&stats.skippedNoise))
		fmt.Fprintf(w, "ebpf_tracer_skipped_fd_filter %d\n", atomic.LoadUint64(&stats.skippedFDFilter))
		fmt.Fprintf(w, "ebpf_tracer_metadata_misses %d\n", atomic.LoadUint64(&stats.metadataMisses))
		fmt.Fprintf(w, "ebpf_tracer_truncated_events %d\n", atomic.LoadUint64(&stats.truncatedEvents))
		fmt.Fprintf(w, "ebpf_tracer_bytes_captured %d\n", atomic.LoadUint64(&stats.bytesCaptured))
		fmt.Fprintf(w, "ebpf_tracer_local_queue_depth %d\n", producer.depth())
		fmt.Fprintf(w, "ebpf_tracer_local_queue_capacity %d\n", cap(producer.queue))
		fmt.Fprintf(w, "ebpf_tracer_local_queue_enqueued %d\n", atomic.LoadUint64(&stats.localQueueEnqueued))
		fmt.Fprintf(w, "ebpf_tracer_local_queue_dropped %d\n", atomic.LoadUint64(&stats.localQueueDropped))
		fmt.Fprintf(w, "ebpf_tracer_produce_attempts %d\n", atomic.LoadUint64(&stats.produceAttempts))
		fmt.Fprintf(w, "ebpf_tracer_produce_errors %d\n", atomic.LoadUint64(&stats.produceErrors))
		fmt.Fprintf(w, "ebpf_tracer_produce_queue_full %d\n", atomic.LoadUint64(&stats.produceQueueFull))
		fmt.Fprintf(w, "ebpf_tracer_delivery_successes %d\n", atomic.LoadUint64(&stats.deliverySuccesses))
		fmt.Fprintf(w, "ebpf_tracer_delivery_failures %d\n", atomic.LoadUint64(&stats.deliveryFailures))
		fmt.Fprintf(w, "ebpf_tracer_ring_read_errors %d\n", atomic.LoadUint64(&stats.ringReadErrors))
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		log.Printf("Health server listening addr=%s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("health server failed: %v", err)
		}
	}()
	return srv
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("failed to write health response: %v", err)
	}
}
