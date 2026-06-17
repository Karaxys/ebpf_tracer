package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Karaxys/ebpf_tracer/pkg/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
)

const (
	eventTypeData   = 0
	eventTypeClose  = 1
	eventTypeSocket = 2

	dropRingbufReserve = 0
	dropCopyWrite      = 1
	dropCopyRead       = 2
	dropIovRead        = 3
	dropMissingContext = 4
	dropNoise          = 5
	dropMetricMax      = 8
)

type fdKey struct {
	pid uint32
	fd  uint32
}

type fdCacheEntry struct {
	isAllowed bool
	checkedAt time.Time
}

type fdClassifier struct {
	mu              sync.Mutex
	cache           map[fdKey]fdCacheEntry
	ttl             time.Duration
	targetPorts     portSet
	ignorePorts     portSet
	captureInbound  bool
	captureOutbound bool
}

func newFDClassifier(ttl time.Duration, targetPorts, ignorePorts portSet, captureInbound, captureOutbound bool) *fdClassifier {
	return &fdClassifier{
		cache:           make(map[fdKey]fdCacheEntry),
		ttl:             ttl,
		targetPorts:     targetPorts,
		ignorePorts:     ignorePorts,
		captureInbound:  captureInbound,
		captureOutbound: captureOutbound,
	}
}

func (c *fdClassifier) isAllowed(pid, fd uint32) bool {
	if fd <= 2 {
		return false
	}

	now := time.Now()
	key := fdKey{pid: pid, fd: fd}

	c.mu.Lock()
	if entry, ok := c.cache[key]; ok && now.Sub(entry.checkedAt) < c.ttl {
		c.mu.Unlock()
		return entry.isAllowed
	}
	c.mu.Unlock()

	isAllowed := c.classifyFD(pid, fd)

	c.mu.Lock()
	c.cache[key] = fdCacheEntry{isAllowed: isAllowed, checkedAt: now}
	if len(c.cache) > 16384 {
		cutoff := now.Add(-2 * c.ttl)
		for k, v := range c.cache {
			if v.checkedAt.Before(cutoff) {
				delete(c.cache, k)
			}
		}
	}
	c.mu.Unlock()

	return isAllowed
}

func (c *fdClassifier) classifyFD(pid, fd uint32) bool {
	conn, ok := resolveConnection(pid, fd)
	if !ok {
		return false
	}

	if c.ignorePorts.matchesAny(conn.SrcPort, conn.DstPort) {
		return false
	}

	if conn.Role == "inbound" && !c.captureInbound {
		return false
	}
	if conn.Role == "outbound" && !c.captureOutbound {
		return false
	}

	if len(c.targetPorts) == 0 {
		return true
	}

	return c.targetPorts.matchesAny(conn.SrcPort, conn.DstPort)
}

func socketInode(pid, fd uint32) (string, error) {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	if err != nil {
		return "", err
	}

	if !strings.HasPrefix(target, "socket:[") {
		return "", nil
	}

	start := strings.IndexByte(target, '[')
	end := strings.IndexByte(target, ']')
	if start < 0 || end < 0 || end <= start+1 {
		return "", fmt.Errorf("invalid socket target %q", target)
	}

	return target[start+1 : end], nil
}

func matchTCPInode(pid uint32, inode string, port int, ipv6 bool) bool {
	path := fmt.Sprintf("/proc/%d/net/tcp", pid)
	if ipv6 {
		path = fmt.Sprintf("/proc/%d/net/tcp6", pid)
	}

	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}

		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		if fields[9] != inode {
			continue
		}

		if port <= 0 {
			return true
		}

		localPort := parseHexPort(fields[1])
		remotePort := parseHexPort(fields[2])
		if localPort == port || remotePort == port {
			return true
		}
	}

	return false
}

func parseHexPort(addr string) int {
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		return -1
	}

	v, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return -1
	}

	return int(v)
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

// ApiEvent represents the JSON structure send to Kafka
type ApiEvent struct {
	SchemaVersion string             `json:"schema_version,omitempty"`
	CaptureSource string             `json:"capture_source,omitempty"`
	CaptureMode   string             `json:"capture_mode,omitempty"`
	Timestamp     uint64             `json:"timestamp"`
	PID           uint32             `json:"pid"`
	TID           uint32             `json:"tid"`
	FD            uint32             `json:"fd"`
	Generation    uint32             `json:"generation"`
	Seq           uint32             `json:"seq"`
	ChunkIndex    uint16             `json:"chunk_index"`
	ChunkCount    uint16             `json:"chunk_count"`
	Direction     uint8              `json:"direction"`
	EventType     uint8              `json:"event_type"`
	Flags         uint8              `json:"flags"`
	OriginalSize  uint32             `json:"original_size,omitempty"`
	Size          uint32             `json:"size"`
	Payload       []byte             `json:"payload"`
	Connection    connectionMetadata `json:"connection,omitempty"`
	Process       processMetadata    `json:"process,omitempty"`
	Container     containerMetadata  `json:"container,omitempty"`
	Loss          lossMetadata       `json:"loss,omitempty"`
}

type kernelDropSnapshot struct {
	ringbufReserve uint64
	copyWrite      uint64
	copyRead       uint64
	iovRead        uint64
	missingContext uint64
	noise          uint64
}

type agentStats struct {
	ringRecords        uint64
	decodedEvents      uint64
	decodeErrors       uint64
	dataEvents         uint64
	closeEvents        uint64
	socketEvents       uint64
	skippedNoise       uint64
	skippedFDFilter    uint64
	metadataMisses     uint64
	truncatedEvents    uint64
	bytesCaptured      uint64
	marshalErrors      uint64
	produceErrors      uint64
	produceQueueFull   uint64
	localQueueEnqueued uint64
	localQueueDropped  uint64
	produceAttempts    uint64
	deliveryFailures   uint64
	deliverySuccesses  uint64
	ringReadErrors     uint64
}

func kafkaEventKey(event ApiEvent) []byte {
	return []byte(fmt.Sprintf("%d-%d-%d", event.PID, event.FD, event.Generation))
}

func readDropMetric(dropMap *ebpf.Map, idx uint32) uint64 {
	var value uint64
	if err := dropMap.Lookup(&idx, &value); err != nil {
		return 0
	}
	return value
}

func readKernelDropSnapshot(dropMap *ebpf.Map) kernelDropSnapshot {
	if dropMap == nil {
		return kernelDropSnapshot{}
	}

	return kernelDropSnapshot{
		ringbufReserve: readDropMetric(dropMap, dropRingbufReserve),
		copyWrite:      readDropMetric(dropMap, dropCopyWrite),
		copyRead:       readDropMetric(dropMap, dropCopyRead),
		iovRead:        readDropMetric(dropMap, dropIovRead),
		missingContext: readDropMetric(dropMap, dropMissingContext),
		noise:          readDropMetric(dropMap, dropNoise),
	}
}

func logKernelDropDeltas(prev, curr kernelDropSnapshot) {
	log.Printf(
		"kernel_drops delta reserve=%d copy_write=%d copy_read=%d iov_read=%d missing_ctx=%d noise=%d",
		curr.ringbufReserve-prev.ringbufReserve,
		curr.copyWrite-prev.copyWrite,
		curr.copyRead-prev.copyRead,
		curr.iovRead-prev.iovRead,
		curr.missingContext-prev.missingContext,
		curr.noise-prev.noise,
	)
}

func logAgentStats(prefix string, stats *agentStats) {
	log.Printf(
		"agent_stats[%s] ring_records=%d decoded=%d decode_errors=%d data=%d close=%d socket=%d skipped_noise=%d skipped_fd_filter=%d metadata_misses=%d truncated=%d bytes_captured=%d marshal_errors=%d local_queue_enqueued=%d local_queue_dropped=%d produce_attempts=%d produce_errors=%d produce_queue_full=%d delivery_successes=%d delivery_failures=%d ring_read_errors=%d",
		prefix,
		atomic.LoadUint64(&stats.ringRecords),
		atomic.LoadUint64(&stats.decodedEvents),
		atomic.LoadUint64(&stats.decodeErrors),
		atomic.LoadUint64(&stats.dataEvents),
		atomic.LoadUint64(&stats.closeEvents),
		atomic.LoadUint64(&stats.socketEvents),
		atomic.LoadUint64(&stats.skippedNoise),
		atomic.LoadUint64(&stats.skippedFDFilter),
		atomic.LoadUint64(&stats.metadataMisses),
		atomic.LoadUint64(&stats.truncatedEvents),
		atomic.LoadUint64(&stats.bytesCaptured),
		atomic.LoadUint64(&stats.marshalErrors),
		atomic.LoadUint64(&stats.localQueueEnqueued),
		atomic.LoadUint64(&stats.localQueueDropped),
		atomic.LoadUint64(&stats.produceAttempts),
		atomic.LoadUint64(&stats.produceErrors),
		atomic.LoadUint64(&stats.produceQueueFull),
		atomic.LoadUint64(&stats.deliverySuccesses),
		atomic.LoadUint64(&stats.deliveryFailures),
		atomic.LoadUint64(&stats.ringReadErrors),
	)
}

func main() {
	// Parse target and production capture controls.
	targetPID := flag.Int("pid", 0, "The PID of the target application. Required for target-mode=pid or pid-tree")
	targetModeRaw := flag.String("target-mode", "pid", "Targeting mode: pid, pid-tree, container, all-pids")
	containerName := flag.String("container", "", "Container name or ID for target-mode=container")
	targetRefreshInterval := flag.Duration("target-refresh-interval", 5*time.Second, "Target PID refresh interval for dynamic workers/containers")
	allowAllPIDs := flag.Bool("allow-all-pids", false, "Required safety acknowledgement for target-mode=all-pids")
	bootstrapServers := flag.String("kafka-bootstrap", "localhost:9092", "Kafka bootstrap servers")
	topicName := flag.String("topic", "raw-network-traffic", "Kafka topic for raw events")
	targetPort := flag.Int("target-port", 0, "Deprecated: single target TCP port. Prefer -target-ports")
	targetPortsRaw := flag.String("target-ports", "", "Comma-separated TCP ports to capture. Empty allows any non-ignored socket port")
	ignorePortsRaw := flag.String("ignore-ports", "9092,27017,6379", "Comma-separated TCP ports to ignore by default, e.g. Kafka/Mongo/Redis")
	fdFilterEnabled := flag.Bool("fd-filter", true, "Enable default user-space socket/port FD filtering via /proc")
	allowNonSocketFDs := flag.Bool("allow-non-socket-fds", false, "Debug mode: forward non-socket FDs instead of default socket-only capture")
	captureInbound := flag.Bool("capture-inbound", true, "Capture inbound/server-side socket traffic")
	captureOutbound := flag.Bool("capture-outbound", true, "Capture outbound/client-side socket traffic")
	statsInterval := flag.Duration("stats-interval", 10*time.Second, "Periodic agent/kernel stats log interval")
	metadataTTL := flag.Duration("metadata-cache-ttl", 15*time.Second, "Connection/process/container metadata cache TTL")
	kafkaQueueMessages := flag.Int("kafka-queue-max-messages", 200000, "Kafka producer queue.buffering.max.messages")
	kafkaQueueKBytes := flag.Int("kafka-queue-max-kbytes", 262144, "Kafka producer queue.buffering.max.kbytes")
	localQueueEvents := flag.Int("local-queue-events", 50000, "Bounded in-agent queue size before Kafka producer")
	backpressureRaw := flag.String("backpressure-mode", "best-effort", "Backpressure mode: best-effort, strict, drop-newest, drop-oldest")
	healthAddr := flag.String("health-addr", "127.0.0.1:7071", "HTTP health/metrics listen address; empty disables")
	flag.Parse()

	mode, err := parseTargetMode(*targetModeRaw)
	if err != nil {
		log.Fatal(err)
	}

	targetPorts, err := parsePortSet(*targetPortsRaw)
	if err != nil {
		log.Fatalf("invalid -target-ports: %v", err)
	}
	if *targetPort > 0 {
		targetPorts[*targetPort] = struct{}{}
	}
	ignorePorts, err := parsePortSet(*ignorePortsRaw)
	if err != nil {
		log.Fatalf("invalid -ignore-ports: %v", err)
	}
	backpressure, err := parseBackpressureMode(*backpressureRaw)
	if err != nil {
		log.Fatal(err)
	}

	// Allow the current process to lock memory for eBPF resources
	if err := bpf.SetRlimit(); err != nil {
		log.Fatalf("Failed to remove rlimit: %v", err)
	}

	// Load pre-compiled eBPF objects into the kernel
	objs := bpf.Objects{}
	if err := bpf.LoadObjects(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %v", err)
	}
	defer objs.Close()

	// Resolve targets and inform the kernel which PIDs to trace.
	targetMgr := newTargetManager(targetConfig{
		mode:            mode,
		pid:             *targetPID,
		container:       *containerName,
		refreshInterval: *targetRefreshInterval,
		allowAllPIDs:    *allowAllPIDs,
	}, objs.TargetPids)
	if _, err := targetMgr.refresh(); err != nil {
		log.Fatalf("Failed to resolve initial targets: %v", err)
	}
	log.Printf("Successfully injected eBPF program. target_mode=%s", mode)

	// Attach tracepoints to the syscalls
	tpWrite, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TraceSysEnterWrite, nil)
	if err != nil {
		log.Fatalf("Opening tracepoint sys_enter_write: %s", err)
	}
	defer tpWrite.Close()

	tpReadEnter, err := link.Tracepoint("syscalls", "sys_enter_read", objs.TraceSysEnterRead, nil)
	if err != nil {
		log.Fatalf("Opening tracepoint sys_enter_read: %s", err)
	}
	defer tpReadEnter.Close()

	tpReadExit, err := link.Tracepoint("syscalls", "sys_exit_read", objs.TraceSysExitRead, nil)
	if err != nil {
		log.Fatalf("Opening tracepoint sys_exit_read: %s", err)
	}
	defer tpReadExit.Close()

	tpWritev, err := link.Tracepoint("syscalls", "sys_enter_writev", objs.TraceSysEnterWritev, nil)
	if err != nil {
		log.Fatalf("Opening tracepoint sys_enter_writev: %s", err)
	}
	defer tpWritev.Close()

	tpSendto, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.TraceSysEnterSendto, nil)
	if err != nil {
		log.Fatalf("Opening tracepoint sys_enter_sendto: %s", err)
	}
	defer tpSendto.Close()

	tpReadvEnter, err := link.Tracepoint("syscalls", "sys_enter_readv", objs.TraceSysEnterReadv, nil)
	if err != nil {
		log.Fatalf("Opening tracepoint sys_enter_readv: %s", err)
	}
	defer tpReadvEnter.Close()

	tpReadvExit, err := link.Tracepoint("syscalls", "sys_exit_readv", objs.TraceSysExitReadv, nil)
	if err != nil {
		log.Fatalf("Opening tracepoint sys_exit_readv: %s", err)
	}
	defer tpReadvExit.Close()

	tpRecvfromEnter, err := link.Tracepoint("syscalls", "sys_enter_recvfrom", objs.TraceSysEnterRecvfrom, nil)
	if err != nil {
		log.Fatalf("Opening tracepoint sys_enter_recvfrom: %s", err)
	}
	defer tpRecvfromEnter.Close()

	tpRecvfromExit, err := link.Tracepoint("syscalls", "sys_exit_recvfrom", objs.TraceSysExitRecvfrom, nil)
	if err != nil {
		log.Fatalf("Opening tracepoint sys_exit_recvfrom: %s", err)
	}
	defer tpRecvfromExit.Close()

	tpClose, err := link.Tracepoint("syscalls", "sys_enter_close", objs.TraceSysEnterClose, nil)
	if err != nil {
		log.Fatalf("Opening tracepoint sys_enter_close: %s", err)
	}
	defer tpClose.Close()

	tpAccept, err := link.Tracepoint("syscalls", "sys_exit_accept", objs.TraceSysExitAccept, nil)
	if err != nil {
		log.Printf("Opening tracepoint sys_exit_accept failed: %s", err)
	} else {
		defer tpAccept.Close()
	}

	tpAccept4, err := link.Tracepoint("syscalls", "sys_exit_accept4", objs.TraceSysExitAccept4, nil)
	if err != nil {
		log.Printf("Opening tracepoint sys_exit_accept4 failed: %s", err)
	} else {
		defer tpAccept4.Close()
	}

	// Initialize the Kafka Producer
	p, err := kafka.NewProducer(&kafka.ConfigMap{
		"bootstrap.servers":            *bootstrapServers,
		"enable.idempotence":           true,
		"acks":                         "all",
		"compression.type":             "lz4",
		"queue.buffering.max.messages": *kafkaQueueMessages,
		"queue.buffering.max.kbytes":   *kafkaQueueKBytes,
		"queue.buffering.max.ms":       10,
	})
	if err != nil {
		log.Fatalf("Failed to create Kafka producer: %s", err)
	}
	defer p.Close()

	// Go routine to handle Kafka delivery reports asynchronously
	stats := &agentStats{}
	queuedProducer := newQueuedProducer(p, *topicName, backpressure, *localQueueEvents, stats)
	defer queuedProducer.close()
	log.Printf("Producer backpressure configured mode=%s local_queue_events=%d kafka_queue_messages=%d kafka_queue_kbytes=%d", backpressure, *localQueueEvents, *kafkaQueueMessages, *kafkaQueueKBytes)
	if *healthAddr != "" {
		healthSrv := startHealthServer(*healthAddr, stats, queuedProducer)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = healthSrv.Shutdown(ctx)
		}()
	}
	go func() {
		for e := range p.Events() {
			switch ev := e.(type) {
			case *kafka.Message:
				if ev.TopicPartition.Error != nil {
					atomic.AddUint64(&stats.deliveryFailures, 1)
					log.Printf("Delivery failed: %v\n", ev.TopicPartition)
				} else {
					atomic.AddUint64(&stats.deliverySuccesses, 1)
				}
			}
		}
	}()

	// Open the BPF Ring Buffer Reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	log.Println("Listening for events... Press Ctrl+C to exit.")

	// Listen for OS signals to cleanly exit
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stopper)

	stopCh := make(chan struct{})
	go targetMgr.run(stopCh)
	defer close(stopCh)

	go func() {
		<-stopper
		log.Println("Received signal, exiting...")
		rd.Close()
	}()

	go func() {
		ticker := time.NewTicker(*statsInterval)
		defer ticker.Stop()

		previous := readKernelDropSnapshot(objs.DropMetrics)
		for range ticker.C {
			current := readKernelDropSnapshot(objs.DropMetrics)
			logKernelDropDeltas(previous, current)
			logAgentStats("periodic", stats)
			previous = current
		}
	}()

	// High-Speed Polling Loop
	var bpfEvent bpf.ApiEvent // Auto-generated struct from C code
	metadata := newMetadataResolver(*metadataTTL)
	var flowFilter *flowFilter
	if *fdFilterEnabled {
		flowFilter = newFlowFilter(*metadataTTL, targetPorts, ignorePorts, *captureInbound, *captureOutbound)
		log.Printf("Flow filter enabled target_ports=%v ignore_ports=%v inbound=%t outbound=%t", sortedPortSet(targetPorts), sortedPortSet(ignorePorts), *captureInbound, *captureOutbound)
	} else if *allowNonSocketFDs {
		log.Printf("WARNING: fd filter disabled and non-socket FDs allowed; use only for debugging")
	}

loop:
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Ring buffer closed")
				break loop
			}
			atomic.AddUint64(&stats.ringReadErrors, 1)
			log.Printf("Error reading from ringbuf: %s", err)
			continue
		}
		atomic.AddUint64(&stats.ringRecords, 1)

		// Deserialize the raw kernel bytes into our Go struct
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &bpfEvent); err != nil {
			atomic.AddUint64(&stats.decodeErrors, 1)
			log.Printf("Failed to parse ringbuf event: %v", err)
			continue
		}
		atomic.AddUint64(&stats.decodedEvents, 1)

		// Create the Kafka payload, slicing the payload array to the actual intercepted Size
		payloadSize := int(bpfEvent.Size)
		if payloadSize > len(bpfEvent.Payload) {
			payloadSize = len(bpfEvent.Payload)
		}

		originalSize := bpfEvent.Size
		capturedSize := uint32(payloadSize)
		loss := lossMetadata{}
		if originalSize > capturedSize {
			loss = lossMetadata{Truncated: true, OriginalSize: originalSize, CapturedSize: capturedSize, Reason: "payload_exceeded_agent_struct_size"}
			atomic.AddUint64(&stats.truncatedEvents, 1)
		}

		conn, proc, container, metadataOK := metadata.resolve(bpfEvent.Pid, bpfEvent.Fd)
		if !metadataOK && bpfEvent.Fd > 2 {
			atomic.AddUint64(&stats.metadataMisses, 1)
		}

		event := ApiEvent{
			SchemaVersion: "raw.network.v1",
			CaptureSource: "ebpf",
			CaptureMode:   string(mode),
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
			Payload:       bpfEvent.Payload[:payloadSize],
			Connection:    conn,
			Process:       proc,
			Container:     container,
			Loss:          loss,
		}
		atomic.AddUint64(&stats.bytesCaptured, uint64(capturedSize))
		switch event.EventType {
		case eventTypeData:
			atomic.AddUint64(&stats.dataEvents, 1)
		case eventTypeClose:
			atomic.AddUint64(&stats.closeEvents, 1)
		case eventTypeSocket:
			atomic.AddUint64(&stats.socketEvents, 1)
		}

		if event.EventType == eventTypeData && isCounterNoise(event.Payload) {
			atomic.AddUint64(&stats.skippedNoise, 1)
			continue
		}

		if flowFilter != nil && !flowFilter.allow(event, metadataOK) {
			atomic.AddUint64(&stats.skippedFDFilter, 1)
			continue
		}
		if event.EventType == eventTypeSocket {
			continue
		}
		if flowFilter == nil && !*allowNonSocketFDs && event.FD <= 2 {
			atomic.AddUint64(&stats.skippedFDFilter, 1)
			continue
		}

		jsonBytes, err := json.Marshal(event)
		if err != nil {
			atomic.AddUint64(&stats.marshalErrors, 1)
			log.Printf("Failed to marshal JSON: %v", err)
			continue
		}

		queuedProducer.submit(kafkaEventKey(event), jsonBytes)
	}

	logAgentStats("shutdown", stats)
	log.Println("Flushing Kafka producer before shutdown...")
	p.Flush(5000)
}
