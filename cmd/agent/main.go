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
	dropFDFilter       = 6
	dropDirection      = 7
	dropPortFilter     = 8
	dropCgroupFilter   = 9
	dropMetricMax      = 10

	captureConfigMaxPayloadSize = 0
	captureConfigCaptureReads   = 1
	captureConfigCaptureWrites  = 2
	captureConfigCaptureStdio   = 3
	captureConfigTargetPorts    = 4
	captureConfigCgroupFilter   = 5

	maxKernelPayloadSize = 4096 * 4

	kernelAFInet  = 2
	kernelAFInet6 = 10

	socketRoleInbound  = 1
	socketRoleOutbound = 2

	socketTupleLocal  = 1
	socketTupleRemote = 2
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
	if err := scanner.Err(); err != nil {
		return false
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
	fdFilter       uint64
	direction      uint64
	portFilter     uint64
	cgroupFilter   uint64
}

type agentMetricsEvent struct {
	SchemaVersion   string            `json:"schema_version"`
	CaptureSource   string            `json:"capture_source"`
	CaptureMode     string            `json:"capture_mode"`
	CreatedAt       string            `json:"created_at"`
	Stats           map[string]uint64 `json:"stats"`
	KernelDrops     map[string]uint64 `json:"kernel_drops"`
	LocalQueueDepth int               `json:"local_queue_depth"`
}

type agentStats struct {
	ringRecords             uint64
	decodedEvents           uint64
	decodeErrors            uint64
	dataEvents              uint64
	closeEvents             uint64
	socketEvents            uint64
	skippedNoise            uint64
	skippedFDFilter         uint64
	metadataMisses          uint64
	metadataCacheHits       uint64
	metadataProcHits        uint64
	metadataProcMisses      uint64
	kernelTupleFallbacks    uint64
	truncatedEvents         uint64
	bytesCaptured           uint64
	marshalErrors           uint64
	produceErrors           uint64
	produceQueueFull        uint64
	kafkaErrors             uint64
	brokerUnavailableEvents uint64
	brokerCircuitSpool      uint64
	localQueueEnqueued      uint64
	localQueueDropped       uint64
	produceAttempts         uint64
	deliveryFailures        uint64
	deliverySuccesses       uint64
	spoolWrites             uint64
	spoolWriteErrors        uint64
	spoolReplayed           uint64
	spoolRetained           uint64
	ringReadErrors          uint64
}

func publishAgentMetrics(producer *kafka.Producer, topic string, mode targetMode, stats *agentStats, drops kernelDropSnapshot, queueDepth int) {
	topic = strings.TrimSpace(topic)
	if producer == nil || topic == "" || stats == nil {
		return
	}
	event := agentMetricsEvent{
		SchemaVersion:   "agent.metrics.v1",
		CaptureSource:   "ebpf",
		CaptureMode:     string(mode),
		CreatedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		LocalQueueDepth: queueDepth,
		Stats: map[string]uint64{
			"ring_records":              atomic.LoadUint64(&stats.ringRecords),
			"decoded_events":            atomic.LoadUint64(&stats.decodedEvents),
			"decode_errors":             atomic.LoadUint64(&stats.decodeErrors),
			"data_events":               atomic.LoadUint64(&stats.dataEvents),
			"close_events":              atomic.LoadUint64(&stats.closeEvents),
			"socket_events":             atomic.LoadUint64(&stats.socketEvents),
			"skipped_noise":             atomic.LoadUint64(&stats.skippedNoise),
			"skipped_fd_filter":         atomic.LoadUint64(&stats.skippedFDFilter),
			"metadata_misses":           atomic.LoadUint64(&stats.metadataMisses),
			"metadata_cache_hits":       atomic.LoadUint64(&stats.metadataCacheHits),
			"metadata_proc_hits":        atomic.LoadUint64(&stats.metadataProcHits),
			"metadata_proc_misses":      atomic.LoadUint64(&stats.metadataProcMisses),
			"kernel_tuple_fallbacks":    atomic.LoadUint64(&stats.kernelTupleFallbacks),
			"truncated_events":          atomic.LoadUint64(&stats.truncatedEvents),
			"bytes_captured":            atomic.LoadUint64(&stats.bytesCaptured),
			"marshal_errors":            atomic.LoadUint64(&stats.marshalErrors),
			"produce_attempts":          atomic.LoadUint64(&stats.produceAttempts),
			"produce_errors":            atomic.LoadUint64(&stats.produceErrors),
			"produce_queue_full":        atomic.LoadUint64(&stats.produceQueueFull),
			"kafka_errors":              atomic.LoadUint64(&stats.kafkaErrors),
			"broker_unavailable_events": atomic.LoadUint64(&stats.brokerUnavailableEvents),
			"broker_circuit_spool":      atomic.LoadUint64(&stats.brokerCircuitSpool),
			"delivery_successes":        atomic.LoadUint64(&stats.deliverySuccesses),
			"delivery_failures":         atomic.LoadUint64(&stats.deliveryFailures),
			"spool_writes":              atomic.LoadUint64(&stats.spoolWrites),
			"spool_write_errors":        atomic.LoadUint64(&stats.spoolWriteErrors),
			"spool_replayed":            atomic.LoadUint64(&stats.spoolReplayed),
			"spool_retained":            atomic.LoadUint64(&stats.spoolRetained),
			"ring_read_errors":          atomic.LoadUint64(&stats.ringReadErrors),
		},
		KernelDrops: map[string]uint64{
			"ringbuf_reserve": drops.ringbufReserve,
			"copy_write":      drops.copyWrite,
			"copy_read":       drops.copyRead,
			"iov_read":        drops.iovRead,
			"missing_context": drops.missingContext,
			"noise":           drops.noise,
			"fd_filter":       drops.fdFilter,
			"direction":       drops.direction,
			"port_filter":     drops.portFilter,
			"cgroup_filter":   drops.cgroupFilter,
		},
	}
	payload, err := json.Marshal(event)
	if err != nil {
		atomic.AddUint64(&stats.marshalErrors, 1)
		return
	}
	if err := producer.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &topic, Partition: kafka.PartitionAny},
		Key:            []byte("agent.metrics"),
		Value:          payload,
	}, nil); err != nil {
		atomic.AddUint64(&stats.produceErrors, 1)
		log.Printf("Failed to produce agent metrics: %v", err)
	}
}

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

func kafkaEventKey(event ApiEvent) []byte {
	return []byte(fmt.Sprintf("%d-%d-%d", event.PID, event.FD, event.Generation))
}

func isBrokerUnavailableKafkaError(err kafka.Error) bool {
	switch err.Code() {
	case kafka.ErrAllBrokersDown, kafka.ErrTransport, kafka.ErrResolve:
		return true
	default:
		return false
	}
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
		fdFilter:       readDropMetric(dropMap, dropFDFilter),
		direction:      readDropMetric(dropMap, dropDirection),
		portFilter:     readDropMetric(dropMap, dropPortFilter),
		cgroupFilter:   readDropMetric(dropMap, dropCgroupFilter),
	}
}

func logKernelDropDeltas(prev, curr kernelDropSnapshot) {
	log.Printf(
		"kernel_drops delta reserve=%d copy_write=%d copy_read=%d iov_read=%d missing_ctx=%d noise=%d fd_filter=%d direction_filter=%d port_filter=%d cgroup_filter=%d",
		curr.ringbufReserve-prev.ringbufReserve,
		curr.copyWrite-prev.copyWrite,
		curr.copyRead-prev.copyRead,
		curr.iovRead-prev.iovRead,
		curr.missingContext-prev.missingContext,
		curr.noise-prev.noise,
		curr.fdFilter-prev.fdFilter,
		curr.direction-prev.direction,
		curr.portFilter-prev.portFilter,
		curr.cgroupFilter-prev.cgroupFilter,
	)
}

func boolToKernelConfig(enabled bool) uint32 {
	if enabled {
		return 1
	}
	return 0
}

func validateKernelMaxPayloadSize(size int) (uint32, error) {
	if size <= 0 || size > maxKernelPayloadSize {
		return 0, fmt.Errorf("kernel max payload size must be between 1 and %d bytes", maxKernelPayloadSize)
	}
	return uint32(size), nil
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

func configureKernelCapture(configMap *ebpf.Map, maxPayload uint32, captureReads, captureWrites, captureStdio, targetPortsEnabled, cgroupFilterEnabled bool) error {
	settings := map[uint32]uint32{
		captureConfigMaxPayloadSize: maxPayload,
		captureConfigCaptureReads:   boolToKernelConfig(captureReads),
		captureConfigCaptureWrites:  boolToKernelConfig(captureWrites),
		captureConfigCaptureStdio:   boolToKernelConfig(captureStdio),
		captureConfigTargetPorts:    boolToKernelConfig(targetPortsEnabled),
		captureConfigCgroupFilter:   boolToKernelConfig(cgroupFilterEnabled),
	}
	for key, value := range settings {
		if err := putKernelCaptureConfig(configMap, key, value); err != nil {
			return err
		}
	}
	return nil
}

func putKernelPortSet(portMap *ebpf.Map, name string, ports portSet) error {
	if portMap == nil {
		return fmt.Errorf("%s map is not loaded", name)
	}
	var enabled uint8 = 1
	for port := range ports {
		if port <= 0 || port > 65535 {
			return fmt.Errorf("%s contains invalid port %d", name, port)
		}
		key := uint16(port)
		if err := portMap.Update(&key, &enabled, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update %s[%d]: %w", name, port, err)
		}
	}
	return nil
}

func clearKernelPortSet(portMap *ebpf.Map, name string) error {
	if portMap == nil {
		return fmt.Errorf("%s map is not loaded", name)
	}
	keys := make([]uint16, 0)
	var key uint16
	var value uint8
	iter := portMap.Iterate()
	for iter.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate %s: %w", name, err)
	}
	for _, key := range keys {
		if err := portMap.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete %s[%d]: %w", name, key, err)
		}
	}
	return nil
}

func replaceKernelPortSet(portMap *ebpf.Map, name string, ports portSet) error {
	if err := clearKernelPortSet(portMap, name); err != nil {
		return err
	}
	return putKernelPortSet(portMap, name, ports)
}

func configureKernelPortFilters(targetMap, ignoredMap *ebpf.Map, targetPorts, ignoredPorts portSet) error {
	if err := replaceKernelPortSet(targetMap, "target_ports", targetPorts); err != nil {
		return err
	}
	if err := replaceKernelPortSet(ignoredMap, "ignored_ports", ignoredPorts); err != nil {
		return err
	}
	return nil
}

func attachOptionalTracepoint(category, name string, prog *ebpf.Program) link.Link {
	tp, err := link.Tracepoint(category, name, prog, nil)
	if err != nil {
		log.Printf("Opening optional tracepoint %s/%s failed: %s", category, name, err)
		return nil
	}
	return tp
}

func newKernelTupleSyncer(tuples *ebpf.Map) *kernelTupleSyncer {
	return &kernelTupleSyncer{
		tuples: tuples,
		synced: make(map[flowKey]kernelSocketTuple),
	}
}

func kernelFamilyFromConnection(conn connectionMetadata) uint16 {
	switch conn.Family {
	case "ipv4":
		return kernelAFInet
	case "ipv6":
		return kernelAFInet6
	default:
		return 0
	}
}

func kernelRoleFromConnection(conn connectionMetadata) uint8 {
	switch conn.Role {
	case "inbound":
		return socketRoleInbound
	case "outbound":
		return socketRoleOutbound
	default:
		return 0
	}
}

func kernelSocketTupleFromConnection(conn connectionMetadata) (kernelSocketTuple, bool) {
	if conn.Protocol != "tcp" {
		return kernelSocketTuple{}, false
	}

	tuple := kernelSocketTuple{
		Family: kernelFamilyFromConnection(conn),
		Role:   kernelRoleFromConnection(conn),
	}
	if conn.SrcPort > 0 && conn.SrcPort <= 65535 {
		tuple.LocalPort = uint16(conn.SrcPort)
		tuple.Flags |= socketTupleLocal
	}
	if conn.DstPort > 0 && conn.DstPort <= 65535 {
		tuple.RemotePort = uint16(conn.DstPort)
		tuple.Flags |= socketTupleRemote
	}
	if tuple.Family == 0 || tuple.Flags == 0 {
		return kernelSocketTuple{}, false
	}
	return tuple, true
}

func (s *kernelTupleSyncer) remember(pid, fd, generation uint32, conn connectionMetadata) {
	if s == nil || s.tuples == nil {
		return
	}

	tuple, ok := kernelSocketTupleFromConnection(conn)
	if !ok {
		return
	}

	key := flowKey{pid: pid, fd: fd, generation: generation}
	s.mu.Lock()
	if existing, ok := s.synced[key]; ok && existing == tuple {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	mapKey := kernelSocketKey{PID: pid, FD: fd, Generation: generation}
	if err := s.tuples.Update(&mapKey, &tuple, ebpf.UpdateAny); err != nil {
		log.Printf("Failed to sync socket tuple to kernel pid=%d fd=%d generation=%d: %v", pid, fd, generation, err)
		return
	}

	s.mu.Lock()
	s.synced[key] = tuple
	if len(s.synced) > 65536 {
		s.synced = make(map[flowKey]kernelSocketTuple)
	}
	s.mu.Unlock()
}

func (s *kernelTupleSyncer) forget(pid, fd, generation uint32) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.synced, flowKey{pid: pid, fd: fd, generation: generation})
	s.mu.Unlock()
}

func connectionFromKernelTuple(event bpf.ApiEvent) (connectionMetadata, bool) {
	if event.SocketTupleFlags == 0 {
		return connectionMetadata{}, false
	}

	conn := connectionMetadata{Protocol: "tcp"}
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
		return connectionMetadata{}, false
	}
	return conn, true
}

func logAgentStats(prefix string, stats *agentStats) {
	log.Printf(
		"agent_stats[%s] ring_records=%d decoded=%d decode_errors=%d data=%d close=%d socket=%d skipped_noise=%d skipped_fd_filter=%d metadata_misses=%d metadata_cache_hits=%d metadata_proc_hits=%d metadata_proc_misses=%d kernel_tuple_fallbacks=%d truncated=%d bytes_captured=%d marshal_errors=%d local_queue_enqueued=%d local_queue_dropped=%d produce_attempts=%d produce_errors=%d produce_queue_full=%d kafka_errors=%d broker_unavailable_events=%d broker_circuit_spool=%d delivery_successes=%d delivery_failures=%d spool_writes=%d spool_write_errors=%d spool_replayed=%d spool_retained=%d ring_read_errors=%d",
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
		atomic.LoadUint64(&stats.metadataCacheHits),
		atomic.LoadUint64(&stats.metadataProcHits),
		atomic.LoadUint64(&stats.metadataProcMisses),
		atomic.LoadUint64(&stats.kernelTupleFallbacks),
		atomic.LoadUint64(&stats.truncatedEvents),
		atomic.LoadUint64(&stats.bytesCaptured),
		atomic.LoadUint64(&stats.marshalErrors),
		atomic.LoadUint64(&stats.localQueueEnqueued),
		atomic.LoadUint64(&stats.localQueueDropped),
		atomic.LoadUint64(&stats.produceAttempts),
		atomic.LoadUint64(&stats.produceErrors),
		atomic.LoadUint64(&stats.produceQueueFull),
		atomic.LoadUint64(&stats.kafkaErrors),
		atomic.LoadUint64(&stats.brokerUnavailableEvents),
		atomic.LoadUint64(&stats.brokerCircuitSpool),
		atomic.LoadUint64(&stats.deliverySuccesses),
		atomic.LoadUint64(&stats.deliveryFailures),
		atomic.LoadUint64(&stats.spoolWrites),
		atomic.LoadUint64(&stats.spoolWriteErrors),
		atomic.LoadUint64(&stats.spoolReplayed),
		atomic.LoadUint64(&stats.spoolRetained),
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
	allPIDsMax := flag.Int("all-pids-max", 512, "Maximum PID count allowed for target-mode=all-pids; set <=0 to disable")
	allPIDsRequireTargetPorts := flag.Bool("all-pids-require-target-ports", true, "Require -target-ports when target-mode=all-pids")
	cgroupFilterEnabled := flag.Bool("cgroup-filter", true, "Enable kernel cgroup allow filtering for container target mode when cgroup IDs are resolvable")
	bootstrapServers := flag.String("kafka-bootstrap", "localhost:9092", "Kafka bootstrap servers")
	topicName := flag.String("topic", "raw-network-traffic", "Kafka topic for raw events")
	backendURL := flag.String("backend-url", os.Getenv("KARAXYS_BACKEND_URL"), "Karaxys backend base URL for agent heartbeat/config polling")
	agentToken := flag.String("agent-token", os.Getenv("KARAXYS_AGENT_TOKEN"), "Karaxys per-agent token for heartbeat/config polling")
	agentControlTimeout := flag.Duration("agent-control-timeout", 10*time.Second, "HTTP timeout for backend heartbeat/config polling")
	heartbeatInterval := flag.Duration("heartbeat-interval", 30*time.Second, "Agent heartbeat interval when backend-url and agent-token are set")
	remoteConfigInterval := flag.Duration("remote-config-interval", 30*time.Second, "Remote config poll interval when backend-url and agent-token are set")
	targetPort := flag.Int("target-port", 0, "Deprecated: single target TCP port. Prefer -target-ports")
	targetPortsRaw := flag.String("target-ports", "", "Comma-separated TCP ports to capture. Empty allows any non-ignored socket port")
	ignorePortsRaw := flag.String("ignore-ports", "9092,27017,6379", "Comma-separated TCP ports to ignore by default, e.g. Kafka/Mongo/Redis")
	fdFilterEnabled := flag.Bool("fd-filter", true, "Enable default user-space socket/port FD filtering via /proc")
	allowNonSocketFDs := flag.Bool("allow-non-socket-fds", false, "Debug mode: forward non-socket FDs instead of default socket-only capture")
	captureInbound := flag.Bool("capture-inbound", true, "Capture inbound/server-side socket traffic")
	captureOutbound := flag.Bool("capture-outbound", true, "Capture outbound/client-side socket traffic")
	captureReadSyscalls := flag.Bool("capture-read-syscalls", true, "Kernel-side gate for read/readv/recvfrom payload capture")
	captureWriteSyscalls := flag.Bool("capture-write-syscalls", true, "Kernel-side gate for write/writev/sendto payload capture")
	maxPayloadSizeRaw := flag.Int("max-payload-size", maxKernelPayloadSize, "Maximum bytes copied per syscall payload in kernel")
	statsInterval := flag.Duration("stats-interval", 10*time.Second, "Periodic agent/kernel stats log interval")
	metadataTTL := flag.Duration("metadata-cache-ttl", 15*time.Second, "Connection/process/container metadata cache TTL")
	kafkaQueueMessages := flag.Int("kafka-queue-max-messages", 200000, "Kafka producer queue.buffering.max.messages")
	kafkaQueueKBytes := flag.Int("kafka-queue-max-kbytes", 262144, "Kafka producer queue.buffering.max.kbytes")
	kafkaMessageTimeoutMS := flag.Int("kafka-message-timeout-ms", 30000, "Kafka producer message.timeout.ms for bounded delivery failure handling")
	kafkaCircuitBreakerDuration := flag.Duration("kafka-circuit-breaker-duration", 15*time.Second, "Duration to spool new events after broker-down producer errors")
	localQueueEvents := flag.Int("local-queue-events", 50000, "Bounded in-agent queue size before Kafka producer")
	spoolFile := flag.String("spool-file", os.Getenv("KARAXYS_AGENT_SPOOL_FILE"), "Optional JSONL disk spool for Kafka produce/local queue failures")
	spoolMaxBytes := flag.Int64("spool-max-bytes", 128*1024*1024, "Maximum bytes for the local disk spool before truncation")
	metricsTopic := flag.String("metrics-topic", "karaxys.agent.metrics", "Kafka topic for periodic agent metrics; empty disables metrics publishing")
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
	if mode == targetModeAllPIDs && *allPIDsRequireTargetPorts && len(targetPorts) == 0 {
		log.Fatal("target-mode=all-pids requires -target-ports unless -all-pids-require-target-ports=false")
	}
	ignorePorts, err := parsePortSet(*ignorePortsRaw)
	if err != nil {
		log.Fatalf("invalid -ignore-ports: %v", err)
	}
	backpressure, err := parseBackpressureMode(*backpressureRaw)
	if err != nil {
		log.Fatal(err)
	}
	spool, err := newDiskSpool(*spoolFile, *spoolMaxBytes)
	if err != nil {
		log.Fatalf("Configuring disk spool: %v", err)
	}
	maxPayloadSize, err := validateKernelMaxPayloadSize(*maxPayloadSizeRaw)
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
	kernelTargetPortsEnabled := *fdFilterEnabled && len(targetPorts) > 0
	kernelCgroupFilterEnabled := *cgroupFilterEnabled && mode == targetModeContainer
	if err := configureKernelCapture(objs.CaptureConfig, maxPayloadSize, *captureReadSyscalls, *captureWriteSyscalls, *allowNonSocketFDs, kernelTargetPortsEnabled, kernelCgroupFilterEnabled); err != nil {
		log.Fatalf("Configuring kernel capture: %v", err)
	}
	if *fdFilterEnabled {
		if err := configureKernelPortFilters(objs.TargetPorts, objs.IgnoredPorts, targetPorts, ignorePorts); err != nil {
			log.Fatalf("Configuring kernel port filters: %v", err)
		}
	}
	log.Printf("Kernel capture configured max_payload_size=%d capture_read_syscalls=%t capture_write_syscalls=%t capture_stdio=%t kernel_target_ports=%t kernel_ignored_ports=%t", maxPayloadSize, *captureReadSyscalls, *captureWriteSyscalls, *allowNonSocketFDs, kernelTargetPortsEnabled, *fdFilterEnabled && len(ignorePorts) > 0)

	// Resolve targets and inform the kernel which PIDs to trace.
	targetMgr := newTargetManager(targetConfig{
		mode:            mode,
		pid:             *targetPID,
		container:       *containerName,
		refreshInterval: *targetRefreshInterval,
		allowAllPIDs:    *allowAllPIDs,
		maxPIDs:         *allPIDsMax,
		cgroupFilter:    kernelCgroupFilterEnabled,
	}, objs.TargetPids, objs.AllowedCgroups)
	if _, err := targetMgr.refresh(); err != nil {
		log.Fatalf("Failed to resolve initial targets: %v", err)
	}
	log.Printf("Successfully injected eBPF program. target_mode=%s", mode)

	// Attach tracepoints to the syscalls
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

	tpSendmsg := attachOptionalTracepoint("syscalls", "sys_enter_sendmsg", objs.TraceSysEnterSendmsg)
	if tpSendmsg != nil {
		defer tpSendmsg.Close()
	}

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
		"message.timeout.ms":           *kafkaMessageTimeoutMS,
	})
	if err != nil {
		log.Fatalf("Failed to create Kafka producer: %s", err)
	}
	defer p.Close()

	// Go routine to handle Kafka delivery reports asynchronously
	stats := &agentStats{}
	queuedProducer := newQueuedProducer(p, *topicName, backpressure, *localQueueEvents, stats, spool, *kafkaCircuitBreakerDuration)
	defer queuedProducer.close()
	log.Printf("Producer backpressure configured mode=%s local_queue_events=%d kafka_queue_messages=%d kafka_queue_kbytes=%d kafka_message_timeout_ms=%d kafka_circuit_breaker_duration=%s", backpressure, *localQueueEvents, *kafkaQueueMessages, *kafkaQueueKBytes, *kafkaMessageTimeoutMS, *kafkaCircuitBreakerDuration)
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
					if kafkaErr, ok := ev.TopicPartition.Error.(kafka.Error); ok && isBrokerUnavailableKafkaError(kafkaErr) {
						queuedProducer.markBrokerUnavailable(kafkaErr)
					}
					if len(ev.Value) > 0 {
						queuedProducer.spoolMessage("delivery_failure", queuedKafkaMessage{key: ev.Key, value: ev.Value})
					}
				} else {
					atomic.AddUint64(&stats.deliverySuccesses, 1)
					queuedProducer.markBrokerAvailable()
				}
			case kafka.Error:
				atomic.AddUint64(&stats.kafkaErrors, 1)
				log.Printf("Kafka producer error: %v", ev)
				if isBrokerUnavailableKafkaError(ev) {
					queuedProducer.markBrokerUnavailable(ev)
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
			publishAgentMetrics(p, *metricsTopic, mode, stats, current, queuedProducer.depth())
			previous = current
		}
	}()

	// High-Speed Polling Loop
	var bpfEvent bpf.ApiEvent // Auto-generated struct from C code
	metadata := newMetadataResolver(*metadataTTL)
	kernelTuples := newKernelTupleSyncer(objs.SocketTuples)
	var flowFilter *flowFilter
	if *fdFilterEnabled {
		flowFilter = newFlowFilter(*metadataTTL, targetPorts, ignorePorts, *captureInbound, *captureOutbound)
		log.Printf("Flow filter enabled target_ports=%v ignore_ports=%v inbound=%t outbound=%t", sortedPortSet(targetPorts), sortedPortSet(ignorePorts), *captureInbound, *captureOutbound)
	} else if *allowNonSocketFDs {
		log.Printf("WARNING: fd filter disabled and non-socket FDs allowed; use only for debugging")
	}
	controlClient := newAgentControlClient(*backendURL, *agentToken, *agentControlTimeout)
	if controlClient != nil {
		go runAgentHeartbeat(stopCh, controlClient, *heartbeatInterval, string(mode), stats, queuedProducer.depth)
		go runAgentRemoteConfig(stopCh, controlClient, *remoteConfigInterval, func(cfg agentRemoteConfig) error {
			return applyRemoteAgentConfig(objs, flowFilter, *fdFilterEnabled, kernelCgroupFilterEnabled, cfg)
		})
		log.Printf("Agent control plane enabled backend_url=%s heartbeat_interval=%s remote_config_interval=%s", *backendURL, *heartbeatInterval, *remoteConfigInterval)
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

		originalSize := bpfEvent.OriginalSize
		if originalSize == 0 {
			originalSize = bpfEvent.Size
		}
		capturedSize := uint32(payloadSize)
		loss := lossMetadata{}
		if originalSize > capturedSize {
			loss = lossMetadata{Truncated: true, OriginalSize: originalSize, CapturedSize: capturedSize, Reason: "payload_exceeded_agent_struct_size"}
			atomic.AddUint64(&stats.truncatedEvents, 1)
		}

		conn, proc, container, metadataOK, metadataSource := metadata.resolveWithSource(bpfEvent.Pid, bpfEvent.Fd, bpfEvent.Generation)
		switch metadataSource {
		case metadataSourceCache:
			atomic.AddUint64(&stats.metadataCacheHits, 1)
		case metadataSourceProc:
			atomic.AddUint64(&stats.metadataProcHits, 1)
		default:
			atomic.AddUint64(&stats.metadataProcMisses, 1)
		}
		if metadataOK {
			kernelTuples.remember(bpfEvent.Pid, bpfEvent.Fd, bpfEvent.Generation, conn)
		} else if kernelConn, ok := connectionFromKernelTuple(bpfEvent); ok {
			conn = kernelConn
			metadataOK = true
			atomic.AddUint64(&stats.kernelTupleFallbacks, 1)
		}
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
		if event.EventType == eventTypeClose {
			kernelTuples.forget(event.PID, event.FD, event.Generation)
			metadata.forget(event.PID, event.FD, event.Generation)
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
