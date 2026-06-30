// karaxys-capture is a self-contained eBPF HTTP traffic capture agent.
// It combines the eBPF ring-buffer reader and the HTTP conversation assembler
// into a single process connected by an in-memory channel — no Kafka required.
//
// Usage (typical Docker run):
//
//	docker run --rm --privileged --network host \
//	    -e KARAXYS_INGEST_URL=https://your-backend/v1/ingest/conversations \
//	    -e KARAXYS_ACCOUNT_TOKEN=<token> \
//	    -v /sys/fs/bpf:/sys/fs/bpf \
//	    karaxys/capture:latest
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Karaxys/ebpf_tracer/pkg/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	channelBufferSize = 50000
	captureMode       = "all-pids"
)

// ── Kernel tuple syncer — mirrors our /proc-resolved connections back into the
// kernel's socket_tuples BPF map so future events get metadata for free. ─────

type kernelSocketKey struct {
	PID        uint32
	FD         uint32
	Generation uint32
}

type kernelSocketTuple struct {
	Family     uint16
	LocalPort  uint16
	RemotePort uint16
	Role       uint8
	Flags      uint8
}

type kernelTupleSyncer struct {
	mu     sync.Mutex
	tuples *ebpf.Map
	synced map[flowKey]kernelSocketTuple
}

func (s *kernelTupleSyncer) remember(pid, fd, generation uint32, conn ConnectionMetadata) {
	if s == nil || s.tuples == nil || conn.Protocol == "" {
		return
	}
	key := flowKey{pid: pid, fd: fd, generation: generation}

	var family uint16
	switch conn.Family {
	case "ipv4":
		family = kernelAFInet
	case "ipv6":
		family = kernelAFInet6
	}

	var role uint8
	switch conn.Role {
	case "inbound":
		role = socketRoleInbound
	case "outbound":
		role = socketRoleOutbound
	}

	var flags uint8
	if conn.SrcPort > 0 {
		flags |= socketTupleLocal
	}
	if conn.DstPort > 0 {
		flags |= socketTupleRemote
	}

	tuple := kernelSocketTuple{
		Family:     family,
		LocalPort:  uint16(conn.SrcPort),
		RemotePort: uint16(conn.DstPort),
		Role:       role,
		Flags:      flags,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.synced[key]; ok && existing == tuple {
		return
	}

	bpfKey := kernelSocketKey{PID: pid, FD: fd, Generation: generation}
	if err := s.tuples.Put(&bpfKey, &tuple); err == nil {
		s.synced[key] = tuple
	}
}

func (s *kernelTupleSyncer) forget(pid, fd, generation uint32) {
	if s == nil || s.tuples == nil {
		return
	}
	key := flowKey{pid: pid, fd: fd, generation: generation}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.synced[key]; !ok {
		return
	}
	bpfKey := kernelSocketKey{PID: pid, FD: fd, Generation: generation}
	_ = s.tuples.Delete(&bpfKey)
	delete(s.synced, key)
}

func newKernelTupleSyncer(tuples *ebpf.Map) *kernelTupleSyncer {
	return &kernelTupleSyncer{
		tuples: tuples,
		synced: make(map[flowKey]kernelSocketTuple),
	}
}

// connectionFromKernelTuple reads the inline socket tuple from a bpf.ApiEvent
// (set by the kernel when it has a cached tuple) and builds a ConnectionMetadata.
func connectionFromKernelTuple(event bpf.ApiEvent) (ConnectionMetadata, bool) {
	if event.SocketTupleFlags == 0 {
		return ConnectionMetadata{}, false
	}
	conn := ConnectionMetadata{Protocol: "tcp"}
	switch event.SocketFamily {
	case 4:
		conn.Family = "ipv4"
	case 6:
		conn.Family = "ipv6"
	}
	switch event.SocketRole {
	case socketRoleInbound:
		conn.Role = "inbound"
	case socketRoleOutbound:
		conn.Role = "outbound"
	}
	if event.SocketTupleFlags&socketTupleLocal != 0 {
		conn.SrcPort = int(event.LocalPort)
	}
	if event.SocketTupleFlags&socketTupleRemote != 0 {
		conn.DstPort = int(event.RemotePort)
	}
	if conn.SrcPort == 0 && conn.DstPort == 0 {
		return ConnectionMetadata{}, false
	}
	return conn, true
}

// ── Kernel config helpers ─────────────────────────────────────────────────────

func boolToKernelConfig(enabled bool) uint32 {
	if enabled {
		return 1
	}
	return 0
}

func putKernelCaptureConfig(configMap *ebpf.Map, key uint32, value uint32) error {
	if configMap == nil {
		return fmt.Errorf("capture_config map is not loaded")
	}
	if err := configMap.Update(&key, &value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update capture_config[%d]: %w", key, err)
	}
	return nil
}

func configureKernelCapture(configMap *ebpf.Map, maxPayload uint32, captureReads, captureWrites bool) error {
	settings := map[uint32]uint32{
		captureConfigMaxPayloadSize: maxPayload,
		captureConfigCaptureReads:   boolToKernelConfig(captureReads),
		captureConfigCaptureWrites:  boolToKernelConfig(captureWrites),
		captureConfigCaptureStdio:   0, // never capture stdio in combined binary
		captureConfigTargetPorts:    0, // using ignorePorts only, not targetPorts
		captureConfigCgroupFilter:   0, // cgroup filter off for all-pids mode
	}
	for key, value := range settings {
		if err := putKernelCaptureConfig(configMap, key, value); err != nil {
			return err
		}
	}
	return nil
}

func configureKernelIgnorePorts(ignoredMap *ebpf.Map, ignorePorts portSet) error {
	if ignoredMap == nil {
		return nil
	}
	var enabled uint8 = 1
	for port := range ignorePorts {
		if port <= 0 || port > 65535 {
			continue
		}
		key := uint16(port)
		if err := ignoredMap.Update(&key, &enabled, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update ignored_ports[%d]: %w", port, err)
		}
	}
	return nil
}

func attachOptionalTracepoint(category, name string, prog *ebpf.Program) link.Link {
	tp, err := link.Tracepoint(category, name, prog, nil)
	if err != nil {
		log.Printf("optional tracepoint %s/%s skipped: %s", category, name, err)
		return nil
	}
	return tp
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	ingestURL    := flag.String("ingest-url", os.Getenv("KARAXYS_INGEST_URL"), "Backend ingest endpoint (required)")
	accountToken := flag.String("account-token", os.Getenv("KARAXYS_ACCOUNT_TOKEN"), "Account-level bearer token (required)")
	agentID      := flag.String("agent-id", os.Getenv("KARAXYS_AGENT_ID"), "Optional stable agent identifier")

	ignorePortsRaw   := flag.String("ignore-ports", "9092,19092,27017,6379,9644,9100", "Comma-separated ports to suppress (Kafka/Mongo/Redis/Prometheus)")
	targetPortsRaw   := flag.String("target-ports", "", "If set, capture only these TCP ports (empty = all non-ignored)")
	maxPayloadSizeRaw := flag.Int("max-payload-size", maxKernelPayloadSize, "Max bytes copied per syscall in kernel")

	captureInbound  := flag.Bool("capture-inbound", true, "Capture inbound/server-side connections")
	captureOutbound := flag.Bool("capture-outbound", true, "Capture outbound/client-side connections")
	captureReads    := flag.Bool("capture-read-syscalls", true, "Kernel gate for read/readv/recvfrom")
	captureWrites   := flag.Bool("capture-write-syscalls", true, "Kernel gate for write/writev/sendto")

	allPIDsMax          := flag.Int("all-pids-max", 8192, "Maximum PID count; set <=0 to disable limit")
	targetRefreshInterval := flag.Duration("target-refresh-interval", 5*time.Second, "Interval to re-scan /proc for new processes")
	metadataTTL         := flag.Duration("metadata-cache-ttl", 15*time.Second, "Connection/process/container metadata cache TTL")
	sessionTTL          := flag.Duration("session-ttl", defaultSessionTTL, "Idle session timeout before forced flush")
	statsInterval       := flag.Duration("stats-interval", defaultStatsInterval, "Periodic stats log interval")
	maxBodyBytes        := flag.Int64("max-body-bytes", defaultMaxBodyBytes, "Max bytes captured per HTTP body")
	httpTimeout         := flag.Duration("http-timeout", defaultHTTPTimeout, "HTTP POST timeout to backend")
	httpMaxRetries      := flag.Int("http-max-retries", defaultHTTPMaxRetries, "Max POST retry attempts per conversation")
	deadLetterFile      := flag.String("dead-letter-file", os.Getenv("KARAXYS_DEAD_LETTER_FILE"), "Optional path to JSONL dead-letter file on emit failure")
	debugPayload        := flag.Bool("debug-payload", false, "Log raw payload routing decisions (verbose)")

	flag.Parse()

	if *ingestURL == "" {
		log.Fatal("--ingest-url (or KARAXYS_INGEST_URL) is required")
	}
	if *accountToken == "" {
		log.Fatal("--account-token (or KARAXYS_ACCOUNT_TOKEN) is required")
	}
	if *maxPayloadSizeRaw <= 0 || *maxPayloadSizeRaw > maxKernelPayloadSize {
		log.Fatalf("--max-payload-size must be between 1 and %d", maxKernelPayloadSize)
	}

	ignorePorts, err := parsePortSet(*ignorePortsRaw)
	if err != nil {
		log.Fatalf("invalid --ignore-ports: %v", err)
	}
	targetPorts, err := parsePortSet(*targetPortsRaw)
	if err != nil {
		log.Fatalf("invalid --target-ports: %v", err)
	}

	// ── eBPF setup ────────────────────────────────────────────────────────────

	if err := bpf.SetRlimit(); err != nil {
		log.Fatalf("Failed to remove rlimit: %v", err)
	}

	objs := bpf.Objects{}
	if err := bpf.LoadObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF objects: %v", err)
	}
	defer objs.Close()

	if err := configureKernelCapture(objs.CaptureConfig, uint32(*maxPayloadSizeRaw), *captureReads, *captureWrites); err != nil {
		log.Fatalf("Configuring kernel capture: %v", err)
	}
	if err := configureKernelIgnorePorts(objs.IgnoredPorts, ignorePorts); err != nil {
		log.Fatalf("Configuring kernel ignored ports: %v", err)
	}

	// ── Target manager (all-pids) ─────────────────────────────────────────────

	targetMgr := newAllPIDsTargetManager(objs.TargetPids, *allPIDsMax)
	if err := targetMgr.refresh(); err != nil {
		log.Fatalf("Initial PID injection: %v", err)
	}
	log.Printf("eBPF target mode: all-pids, max=%d, ignore_ports=%v, target_ports=%v",
		*allPIDsMax, sortedPortSet(ignorePorts), sortedPortSet(targetPorts))

	// ── Tracepoints ───────────────────────────────────────────────────────────

	tpBind := attachOptionalTracepoint("syscalls", "sys_enter_bind", objs.TraceSysEnterBind)
	if tpBind != nil {
		defer tpBind.Close()
	}
	tpConnect := attachOptionalTracepoint("syscalls", "sys_enter_connect", objs.TraceSysEnterConnect)
	if tpConnect != nil {
		defer tpConnect.Close()
	}
	tpAcceptEnter := attachOptionalTracepoint("syscalls", "sys_enter_accept", objs.TraceSysEnterAccept)
	if tpAcceptEnter != nil {
		defer tpAcceptEnter.Close()
	}
	tpAccept4Enter := attachOptionalTracepoint("syscalls", "sys_enter_accept4", objs.TraceSysEnterAccept4)
	if tpAccept4Enter != nil {
		defer tpAccept4Enter.Close()
	}

	tpWrite, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TraceSysEnterWrite, nil)
	if err != nil {
		log.Fatalf("sys_enter_write: %s", err)
	}
	defer tpWrite.Close()

	tpReadEnter, err := link.Tracepoint("syscalls", "sys_enter_read", objs.TraceSysEnterRead, nil)
	if err != nil {
		log.Fatalf("sys_enter_read: %s", err)
	}
	defer tpReadEnter.Close()

	tpReadExit, err := link.Tracepoint("syscalls", "sys_exit_read", objs.TraceSysExitRead, nil)
	if err != nil {
		log.Fatalf("sys_exit_read: %s", err)
	}
	defer tpReadExit.Close()

	tpWritev, err := link.Tracepoint("syscalls", "sys_enter_writev", objs.TraceSysEnterWritev, nil)
	if err != nil {
		log.Fatalf("sys_enter_writev: %s", err)
	}
	defer tpWritev.Close()

	tpSendto, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.TraceSysEnterSendto, nil)
	if err != nil {
		log.Fatalf("sys_enter_sendto: %s", err)
	}
	defer tpSendto.Close()

	tpSendmsg := attachOptionalTracepoint("syscalls", "sys_enter_sendmsg", objs.TraceSysEnterSendmsg)
	if tpSendmsg != nil {
		defer tpSendmsg.Close()
	}

	tpReadvEnter, err := link.Tracepoint("syscalls", "sys_enter_readv", objs.TraceSysEnterReadv, nil)
	if err != nil {
		log.Fatalf("sys_enter_readv: %s", err)
	}
	defer tpReadvEnter.Close()

	tpReadvExit, err := link.Tracepoint("syscalls", "sys_exit_readv", objs.TraceSysExitReadv, nil)
	if err != nil {
		log.Fatalf("sys_exit_readv: %s", err)
	}
	defer tpReadvExit.Close()

	tpRecvfromEnter, err := link.Tracepoint("syscalls", "sys_enter_recvfrom", objs.TraceSysEnterRecvfrom, nil)
	if err != nil {
		log.Fatalf("sys_enter_recvfrom: %s", err)
	}
	defer tpRecvfromEnter.Close()

	tpRecvfromExit, err := link.Tracepoint("syscalls", "sys_exit_recvfrom", objs.TraceSysExitRecvfrom, nil)
	if err != nil {
		log.Fatalf("sys_exit_recvfrom: %s", err)
	}
	defer tpRecvfromExit.Close()

	tpRecvmsgEnter := attachOptionalTracepoint("syscalls", "sys_enter_recvmsg", objs.TraceSysEnterRecvmsg)
	if tpRecvmsgEnter != nil {
		defer tpRecvmsgEnter.Close()
	}
	tpRecvmsgExit := attachOptionalTracepoint("syscalls", "sys_exit_recvmsg", objs.TraceSysExitRecvmsg)
	if tpRecvmsgExit != nil {
		defer tpRecvmsgExit.Close()
	}

	tpClose, err := link.Tracepoint("syscalls", "sys_enter_close", objs.TraceSysEnterClose, nil)
	if err != nil {
		log.Fatalf("sys_enter_close: %s", err)
	}
	defer tpClose.Close()

	tpAccept, err := link.Tracepoint("syscalls", "sys_exit_accept", objs.TraceSysExitAccept, nil)
	if err != nil {
		log.Printf("sys_exit_accept skipped: %s", err)
	} else {
		defer tpAccept.Close()
	}
	tpAccept4, err := link.Tracepoint("syscalls", "sys_exit_accept4", objs.TraceSysExitAccept4, nil)
	if err != nil {
		log.Printf("sys_exit_accept4 skipped: %s", err)
	} else {
		defer tpAccept4.Close()
	}

	// ── Sinks & config ────────────────────────────────────────────────────────

	sink := newHTTPSink(
		*ingestURL, *accountToken,
		*httpTimeout, *httpMaxRetries, defaultHTTPRetryDelay,
		*deadLetterFile,
	)

	cfg := config{
		ingestURL:      *ingestURL,
		accountToken:   *accountToken,
		agentID:        *agentID,
		sessionTTL:     *sessionTTL,
		statsInterval:  *statsInterval,
		maxBodyBytes:   *maxBodyBytes,
		maxStreamBytes: defaultMaxStreamBytes,
		httpTimeout:    *httpTimeout,
		httpMaxRetries: *httpMaxRetries,
		httpRetryDelay: defaultHTTPRetryDelay,
		deadLetterFile: *deadLetterFile,
		debugPayload:   *debugPayload,
		sink:           sink,
	}

	// ── Ring buffer ───────────────────────────────────────────────────────────

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	// ── Signal handling ───────────────────────────────────────────────────────

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stopper)

	stopCh := make(chan struct{})

	// Close ring buffer on signal — causes the capture loop to exit naturally.
	go func() {
		<-stopper
		log.Println("Signal received, shutting down...")
		rd.Close()
	}()

	// ── In-process channel ────────────────────────────────────────────────────

	eventCh := make(chan CaptureEvent, channelBufferSize)

	// ── Processing goroutine ─────────────────────────────────────────────────

	pStats := &processingStats{}
	store  := newSessionStore(*sessionTTL)

	go runSessionCleanup(store, cfg, pStats, stopCh)
	go runProcessingStats(pStats, *statsInterval, stopCh)

	go func() {
		for event := range eventCh {
			atomic.AddUint64(&pStats.received, 1)
			processEvent(store, cfg, pStats, event)
		}
		// Channel closed: flush all remaining sessions before exiting.
		log.Println("Processing goroutine: flushing remaining sessions...")
		logProcessingStats("shutdown", pStats)
	}()

	// ── Target refresh goroutine ──────────────────────────────────────────────

	go targetMgr.run(*targetRefreshInterval, stopCh)

	// ── Metadata + kernel tuple syncer ────────────────────────────────────────

	metaResolver  := newMetadataResolver(*metadataTTL)
	kernelTuples  := newKernelTupleSyncer(objs.SocketTuples)
	filter        := newFlowFilter(*metadataTTL, targetPorts, ignorePorts, *captureInbound, *captureOutbound)

	// ── Capture stats goroutine ───────────────────────────────────────────────

	cStats := &captureStats{}
	go func() {
		ticker := time.NewTicker(*statsInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				logCaptureStats("periodic", cStats)
			}
		}
	}()

	log.Println("karaxys-capture: listening for HTTP traffic. Press Ctrl+C to stop.")

	// ── Ring buffer capture loop ──────────────────────────────────────────────

	var bpfEvent bpf.ApiEvent
loop:
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Ring buffer closed, exiting capture loop.")
				break loop
			}
			atomic.AddUint64(&cStats.ringReadErrors, 1)
			log.Printf("Ring buffer read error: %s", err)
			continue
		}
		atomic.AddUint64(&cStats.ringRecords, 1)

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &bpfEvent); err != nil {
			atomic.AddUint64(&cStats.decodeErrors, 1)
			log.Printf("Failed to decode ring buffer event: %v", err)
			continue
		}
		atomic.AddUint64(&cStats.decodedEvents, 1)

		payloadSize := int(bpfEvent.Size)
		if payloadSize > len(bpfEvent.Payload) {
			payloadSize = len(bpfEvent.Payload)
		}

		originalSize := bpfEvent.OriginalSize
		if originalSize == 0 {
			originalSize = bpfEvent.Size
		}
		capturedSize := uint32(payloadSize)

		loss := LossMetadata{}
		if originalSize > capturedSize {
			loss = LossMetadata{
				Truncated:    true,
				OriginalSize: originalSize,
				CapturedSize: capturedSize,
				Reason:       "payload_exceeded_agent_struct_size",
			}
			atomic.AddUint64(&cStats.truncatedEvents, 1)
		}

		conn, proc, container, metadataOK, src := metaResolver.resolveWithSource(bpfEvent.Pid, bpfEvent.Fd, bpfEvent.Generation)
		switch src {
		case metadataSourceCache:
			atomic.AddUint64(&cStats.metadataCacheHits, 1)
		case metadataSourceProc:
			atomic.AddUint64(&cStats.metadataProcHits, 1)
		default:
			atomic.AddUint64(&cStats.metadataProcMisses, 1)
		}

		if metadataOK {
			kernelTuples.remember(bpfEvent.Pid, bpfEvent.Fd, bpfEvent.Generation, conn)
		} else if kernelConn, ok := connectionFromKernelTuple(bpfEvent); ok {
			conn = kernelConn
			metadataOK = true
			atomic.AddUint64(&cStats.kernelTupleFallbacks, 1)
		}
		if !metadataOK && bpfEvent.Fd > 2 {
			atomic.AddUint64(&cStats.metadataMisses, 1)
		}

		// Payload bytes — copy out of the BPF record buffer before it's recycled.
		payload := make([]byte, payloadSize)
		copy(payload, bpfEvent.Payload[:payloadSize])

		event := CaptureEvent{
			SchemaVersion: "raw.network.v1",
			CaptureSource: "ebpf",
			CaptureMode:   captureMode,
			Timestamp:     bpfEvent.Timestamp,
			PID:           bpfEvent.Pid,
			TID:           bpfEvent.Tid,
			FD:            bpfEvent.Fd,
			Generation:    bpfEvent.Generation,
			Seq:           bpfEvent.Seq,
			ChunkIndex:    bpfEvent.ChunkIndex,
			ChunkCount:    bpfEvent.ChunkCount,
			Direction:     bpfEvent.Direction,
			EventType:     bpfEvent.EventType,
			Flags:         bpfEvent.Flags,
			OriginalSize:  originalSize,
			Size:          capturedSize,
			Payload:       payload,
			Connection:    conn,
			Process:       proc,
			Container:     container,
			Loss:          loss,
		}

		atomic.AddUint64(&cStats.bytesCaptured, uint64(capturedSize))
		switch event.EventType {
		case eventTypeData:
			atomic.AddUint64(&cStats.dataEvents, 1)
		case eventTypeClose:
			atomic.AddUint64(&cStats.closeEvents, 1)
		case eventTypeSocket:
			atomic.AddUint64(&cStats.socketEvents, 1)
		}

		if event.EventType == eventTypeClose {
			kernelTuples.forget(event.PID, event.FD, event.Generation)
			metaResolver.forget(event.PID, event.FD, event.Generation)
		}

		if event.EventType == eventTypeData && isCounterNoise(event.Payload) {
			atomic.AddUint64(&cStats.skippedNoise, 1)
			continue
		}

		if !filter.allow(event, metadataOK) {
			atomic.AddUint64(&cStats.skippedFDFilter, 1)
			continue
		}

		if event.EventType == eventTypeSocket {
			continue
		}

		// Non-blocking send: drop rather than stall the ring buffer reader.
		select {
		case eventCh <- event:
		default:
			atomic.AddUint64(&cStats.channelDropped, 1)
		}
	}

	// ── Shutdown ──────────────────────────────────────────────────────────────

	close(stopCh)
	close(eventCh) // signals processing goroutine to flush and exit

	// Give the processing goroutine a moment to drain the channel.
	time.Sleep(2 * time.Second)

	logCaptureStats("shutdown", cStats)
	log.Println("karaxys-capture exited cleanly.")
}
