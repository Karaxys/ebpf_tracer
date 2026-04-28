package main

import (
	"bufio"
	"bytes"
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
	eventTypeData  = 0
	eventTypeClose = 1

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
	mu    sync.Mutex
	cache map[fdKey]fdCacheEntry
	ttl   time.Duration
	port  int
}

func newFDClassifier(ttl time.Duration, port int) *fdClassifier {
	return &fdClassifier{
		cache: make(map[fdKey]fdCacheEntry),
		ttl:   ttl,
		port:  port,
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
	inode, err := socketInode(pid, fd)
	if err != nil || inode == "" {
		return false
	}

	if matchTCPInode(pid, inode, c.port, false) {
		return true
	}

	return matchTCPInode(pid, inode, c.port, true)
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

// ApiEvent represents the JSON structure we send to Kafka
type ApiEvent struct {
	Timestamp  uint64 `json:"timestamp"`
	PID        uint32 `json:"pid"`
	TID        uint32 `json:"tid"`
	FD         uint32 `json:"fd"`
	Generation uint32 `json:"generation"`
	Seq        uint32 `json:"seq"`
	ChunkIndex uint16 `json:"chunk_index"`
	ChunkCount uint16 `json:"chunk_count"`
	Direction  uint8  `json:"direction"`
	EventType  uint8  `json:"event_type"`
	Flags      uint8  `json:"flags"`
	Size       uint32 `json:"size"`
	Payload    []byte `json:"payload"`
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
	ringRecords       uint64
	decodedEvents     uint64
	decodeErrors      uint64
	dataEvents        uint64
	closeEvents       uint64
	skippedNoise      uint64
	skippedFDFilter   uint64
	marshalErrors     uint64
	produceErrors     uint64
	produceAttempts   uint64
	deliveryFailures  uint64
	deliverySuccesses uint64
	ringReadErrors    uint64
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
		"agent_stats[%s] ring_records=%d decoded=%d decode_errors=%d data=%d close=%d skipped_noise=%d skipped_fd_filter=%d marshal_errors=%d produce_attempts=%d produce_errors=%d delivery_successes=%d delivery_failures=%d ring_read_errors=%d",
		prefix,
		atomic.LoadUint64(&stats.ringRecords),
		atomic.LoadUint64(&stats.decodedEvents),
		atomic.LoadUint64(&stats.decodeErrors),
		atomic.LoadUint64(&stats.dataEvents),
		atomic.LoadUint64(&stats.closeEvents),
		atomic.LoadUint64(&stats.skippedNoise),
		atomic.LoadUint64(&stats.skippedFDFilter),
		atomic.LoadUint64(&stats.marshalErrors),
		atomic.LoadUint64(&stats.produceAttempts),
		atomic.LoadUint64(&stats.produceErrors),
		atomic.LoadUint64(&stats.deliverySuccesses),
		atomic.LoadUint64(&stats.deliveryFailures),
		atomic.LoadUint64(&stats.ringReadErrors),
	)
}

func main() {
	// 1. Parse target PID from command line (FR-2: Target Filtering)
	targetPID := flag.Int("pid", 0, "The PID of the target application (e.g., Node.js/Podman)")
	bootstrapServers := flag.String("kafka-bootstrap", "localhost:9092", "Kafka bootstrap servers")
	topicName := flag.String("topic", "raw-network-traffic", "Kafka topic for raw events")
	targetPort := flag.Int("target-port", 0, "Only forward TCP traffic matching this port. Use 0 to allow any TCP port")
	enableUserFDFilter := flag.Bool("enable-user-fd-filter", false, "Enable user-space fd/port filtering via /proc (debug mode)")
	statsInterval := flag.Duration("stats-interval", 10*time.Second, "Periodic agent/kernel stats log interval")
	flag.Parse()

	if *targetPID == 0 {
		log.Fatalf("Please provide a target PID using -pid <PID>")
	}

	// Allow the current process to lock memory for eBPF resources (NFR-6)
	if err := bpf.SetRlimit(); err != nil {
		log.Fatalf("Failed to remove rlimit: %v", err)
	}

	// 2. Load pre-compiled eBPF objects into the kernel
	objs := bpf.Objects{}
	if err := bpf.LoadObjects(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %v", err)
	}
	defer objs.Close()

	// 3. Inform the kernel which PID to trace by updating the target_pids map
	pidUint32 := uint32(*targetPID)
	traceFlag := uint8(1)
	if err := objs.TargetPids.Put(&pidUint32, &traceFlag); err != nil {
		log.Fatalf("Failed to add target PID to map: %v", err)
	}
	log.Printf("Successfully injected eBPF program. Filtering for PID: %d", *targetPID)

	// 4. Attach tracepoints to the syscalls
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

	// 5. Initialize the Kafka Producer (FR-5: Event Brokering)
	p, err := kafka.NewProducer(&kafka.ConfigMap{
		"bootstrap.servers":            *bootstrapServers,
		"enable.idempotence":           true,
		"acks":                         "all",
		"compression.type":             "lz4",
		"queue.buffering.max.messages": 200000,
		"queue.buffering.max.kbytes":   262144,
		"queue.buffering.max.ms":       10,
	})
	if err != nil {
		log.Fatalf("Failed to create Kafka producer: %s", err)
	}
	defer p.Close()

	// Go routine to handle Kafka delivery reports asynchronously
	stats := &agentStats{}
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

	// 6. Open the BPF Ring Buffer Reader (NFR-3: Zero-Drop Ingestion)
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

	// 7. High-Speed Polling Loop
	var bpfEvent bpf.ApiEvent // Auto-generated struct from our C code
	var fdFilter *fdClassifier
	if *enableUserFDFilter {
		fdFilter = newFDClassifier(15*time.Second, *targetPort)
		log.Printf("User-space fd filter enabled (port=%d)", *targetPort)
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

		event := ApiEvent{
			Timestamp:  bpfEvent.Timestamp,
			PID:        bpfEvent.Pid,
			TID:        bpfEvent.Tid,
			FD:         bpfEvent.Fd,
			Generation: bpfEvent.Generation,
			Seq:        bpfEvent.Seq,
			ChunkIndex: bpfEvent.ChunkIndex,
			ChunkCount: bpfEvent.ChunkCount,
			Direction:  bpfEvent.Direction,
			EventType:  bpfEvent.EventType,
			Flags:      bpfEvent.Flags,
			Size:       uint32(payloadSize),
			Payload:    bpfEvent.Payload[:payloadSize],
		}
		switch event.EventType {
		case eventTypeData:
			atomic.AddUint64(&stats.dataEvents, 1)
		case eventTypeClose:
			atomic.AddUint64(&stats.closeEvents, 1)
		}

		if event.EventType == eventTypeData && isCounterNoise(event.Payload) {
			atomic.AddUint64(&stats.skippedNoise, 1)
			continue
		}

		if fdFilter != nil && event.EventType != eventTypeClose && !fdFilter.isAllowed(event.PID, event.FD) {
			atomic.AddUint64(&stats.skippedFDFilter, 1)
			continue
		}

		jsonBytes, err := json.Marshal(event)
		if err != nil {
			atomic.AddUint64(&stats.marshalErrors, 1)
			log.Printf("Failed to marshal JSON: %v", err)
			continue
		}

		// Push to Kafka non-blockingly
		atomic.AddUint64(&stats.produceAttempts, 1)
		err = p.Produce(&kafka.Message{
			TopicPartition: kafka.TopicPartition{Topic: topicName, Partition: kafka.PartitionAny},
			Key:            kafkaEventKey(event),
			Value:          jsonBytes,
		}, nil)

		if err != nil {
			atomic.AddUint64(&stats.produceErrors, 1)
			log.Printf("Failed to produce to Kafka: %v", err)
		}
	}

	logAgentStats("shutdown", stats)
	log.Println("Flushing Kafka producer before shutdown...")
	p.Flush(5000)
}
