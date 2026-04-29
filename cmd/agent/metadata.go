package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type portSet map[int]struct{}

func parsePortSet(raw string) (portSet, error) {
	set := make(portSet)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		port, err := strconv.Atoi(part)
		if err != nil || port < 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		if port > 0 {
			set[port] = struct{}{}
		}
	}
	return set, nil
}

func (s portSet) contains(port int) bool {
	if len(s) == 0 {
		return false
	}
	_, ok := s[port]
	return ok
}

func (s portSet) matchesAny(ports ...int) bool {
	if len(s) == 0 {
		return false
	}
	for _, port := range ports {
		if s.contains(port) {
			return true
		}
	}
	return false
}

func sortedPortSet(s portSet) []int {
	ports := make([]int, 0, len(s))
	for port := range s {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

func isLikelyHTTPPayload(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	if len(payload) > 64 {
		payload = payload[:64]
	}
	prefixes := [][]byte{
		[]byte("GET "),
		[]byte("POST "),
		[]byte("PUT "),
		[]byte("PATCH "),
		[]byte("DELETE "),
		[]byte("HEAD "),
		[]byte("OPTIONS "),
		[]byte("TRACE "),
		[]byte("CONNECT "),
		[]byte("HTTP/1."),
	}
	for _, prefix := range prefixes {
		if len(payload) >= len(prefix) && string(payload[:len(prefix)]) == string(prefix) {
			return true
		}
	}
	return false
}

type flowKey struct {
	pid        uint32
	fd         uint32
	generation uint32
}

type flowDecision uint8

const (
	flowDecisionAllow flowDecision = iota + 1
	flowDecisionDeny
)

type cachedFlowDecision struct {
	decision  flowDecision
	expiresAt time.Time
}

type flowFilter struct {
	mu              sync.Mutex
	flows           map[flowKey]cachedFlowDecision
	ttl             time.Duration
	targetPorts     portSet
	ignorePorts     portSet
	captureInbound  bool
	captureOutbound bool
}

func newFlowFilter(ttl time.Duration, targetPorts, ignorePorts portSet, captureInbound, captureOutbound bool) *flowFilter {
	return &flowFilter{
		flows:           make(map[flowKey]cachedFlowDecision),
		ttl:             ttl,
		targetPorts:     targetPorts,
		ignorePorts:     ignorePorts,
		captureInbound:  captureInbound,
		captureOutbound: captureOutbound,
	}
}

func (f *flowFilter) allow(event ApiEvent, metadataOK bool) bool {
	if f == nil {
		return true
	}

	now := time.Now()
	key := flowKey{pid: event.PID, fd: event.FD, generation: event.Generation}
	if decision, ok := f.lookup(key, now); ok {
		return decision == flowDecisionAllow
	}

	if metadataOK && event.Connection.Protocol != "" {
		if f.connectionAllowed(event.Connection) {
			f.remember(key, flowDecisionAllow, now)
			return true
		}
		f.remember(key, flowDecisionDeny, now)
		return false
	}

	// For short-lived HTTP sockets, /proc fd metadata can be gone before the
	// user-space agent resolves it. Classify the whole fd generation once the
	// first recognizable HTTP request/response chunk appears, then allow all
	// following body chunks and the close event for that same generation.
	if event.EventType == eventTypeData && isLikelyHTTPPayload(event.Payload) {
		f.remember(key, flowDecisionAllow, now)
		return true
	}

	// Unknown close-only events and body-only chunks before a flow is classified
	// are noise from the capture perspective and should not enter Kafka.
	return false
}

func (f *flowFilter) connectionAllowed(conn connectionMetadata) bool {
	if f.ignorePorts.matchesAny(conn.SrcPort, conn.DstPort) {
		return false
	}
	if conn.Role == "inbound" && !f.captureInbound {
		return false
	}
	if conn.Role == "outbound" && !f.captureOutbound {
		return false
	}
	if len(f.targetPorts) == 0 {
		return true
	}
	return f.targetPorts.matchesAny(conn.SrcPort, conn.DstPort)
}

func (f *flowFilter) lookup(key flowKey, now time.Time) (flowDecision, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cached, ok := f.flows[key]
	if !ok {
		f.cleanupLocked(now)
		return 0, false
	}
	if now.After(cached.expiresAt) {
		delete(f.flows, key)
		f.cleanupLocked(now)
		return 0, false
	}
	return cached.decision, true
}

func (f *flowFilter) remember(key flowKey, decision flowDecision, now time.Time) {
	f.mu.Lock()
	f.flows[key] = cachedFlowDecision{decision: decision, expiresAt: now.Add(f.ttl)}
	f.cleanupLocked(now)
	f.mu.Unlock()
}

func (f *flowFilter) cleanupLocked(now time.Time) {
	if len(f.flows) < 65536 {
		return
	}
	for key, cached := range f.flows {
		if now.After(cached.expiresAt) {
			delete(f.flows, key)
		}
	}
}

type connectionMetadata struct {
	SrcIP    string `json:"src_ip,omitempty"`
	SrcPort  int    `json:"src_port,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	DstPort  int    `json:"dst_port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Family   string `json:"family,omitempty"`
	Role     string `json:"role,omitempty"`
}

type processMetadata struct {
	PID  uint32 `json:"pid,omitempty"`
	Name string `json:"name,omitempty"`
	Exe  string `json:"exe,omitempty"`
}

type containerMetadata struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type lossMetadata struct {
	Truncated       bool   `json:"truncated,omitempty"`
	OriginalSize    uint32 `json:"original_size,omitempty"`
	CapturedSize    uint32 `json:"captured_size,omitempty"`
	Reason          string `json:"reason,omitempty"`
	SequenceGap     bool   `json:"sequence_gap,omitempty"`
	ExpectedNextSeq uint32 `json:"expected_next_seq,omitempty"`
	ActualSeq       uint32 `json:"actual_seq,omitempty"`
}

type metadataResolver struct {
	mu    sync.Mutex
	cache map[fdKey]metadataCacheEntry
	ttl   time.Duration
}

type metadataCacheEntry struct {
	conn      connectionMetadata
	process   processMetadata
	container containerMetadata
	ok        bool
	checkedAt time.Time
}

func newMetadataResolver(ttl time.Duration) *metadataResolver {
	return &metadataResolver{cache: make(map[fdKey]metadataCacheEntry), ttl: ttl}
}

func (r *metadataResolver) resolve(pid, fd uint32) (connectionMetadata, processMetadata, containerMetadata, bool) {
	now := time.Now()
	key := fdKey{pid: pid, fd: fd}

	r.mu.Lock()
	if entry, ok := r.cache[key]; ok && now.Sub(entry.checkedAt) < r.ttl {
		r.mu.Unlock()
		return entry.conn, entry.process, entry.container, entry.ok
	}
	r.mu.Unlock()

	conn, ok := resolveConnection(pid, fd)
	proc := resolveProcess(pid)
	container := resolveContainer(pid)

	r.mu.Lock()
	r.cache[key] = metadataCacheEntry{conn: conn, process: proc, container: container, ok: ok, checkedAt: now}
	if len(r.cache) > 32768 {
		cutoff := now.Add(-2 * r.ttl)
		for k, v := range r.cache {
			if v.checkedAt.Before(cutoff) {
				delete(r.cache, k)
			}
		}
	}
	r.mu.Unlock()

	return conn, proc, container, ok
}

func resolveProcess(pid uint32) processMetadata {
	pidStr := strconv.FormatUint(uint64(pid), 10)
	nameBytes, _ := os.ReadFile(filepath.Join("/proc", pidStr, "comm"))
	exe, _ := os.Readlink(filepath.Join("/proc", pidStr, "exe"))
	return processMetadata{PID: pid, Name: strings.TrimSpace(string(nameBytes)), Exe: exe}
}

func resolveContainer(pid uint32) containerMetadata {
	pidStr := strconv.FormatUint(uint64(pid), 10)
	cgroupBytes, err := os.ReadFile(filepath.Join("/proc", pidStr, "cgroup"))
	if err != nil {
		return containerMetadata{}
	}
	id := extractContainerID(string(cgroupBytes))
	return containerMetadata{ID: id}
}

func extractContainerID(cgroup string) string {
	for _, field := range strings.FieldsFunc(cgroup, func(r rune) bool {
		return r == '/' || r == ':' || r == '\n'
	}) {
		field = strings.TrimSpace(field)
		if len(field) >= 64 && isHex(field[:64]) {
			return field[:64]
		}
		if strings.HasPrefix(field, "docker-") {
			trimmed := strings.TrimPrefix(field, "docker-")
			trimmed = strings.TrimSuffix(trimmed, ".scope")
			if len(trimmed) >= 64 && isHex(trimmed[:64]) {
				return trimmed[:64]
			}
		}
	}
	return ""
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

func resolveConnection(pid, fd uint32) (connectionMetadata, bool) {
	inode, err := socketInode(pid, fd)
	if err != nil || inode == "" {
		return connectionMetadata{}, false
	}

	if conn, ok := findTCPConnection(pid, inode, false); ok {
		return conn, true
	}
	if conn, ok := findTCPConnection(pid, inode, true); ok {
		return conn, true
	}
	return connectionMetadata{}, false
}

func findTCPConnection(pid uint32, inode string, ipv6 bool) (connectionMetadata, bool) {
	path := fmt.Sprintf("/proc/%d/net/tcp", pid)
	family := "ipv4"
	if ipv6 {
		path = fmt.Sprintf("/proc/%d/net/tcp6", pid)
		family = "ipv6"
	}

	f, err := os.Open(path)
	if err != nil {
		return connectionMetadata{}, false
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
		if len(fields) < 10 || fields[9] != inode {
			continue
		}

		localIP, localPort := parseProcNetAddr(fields[1], ipv6)
		remoteIP, remotePort := parseProcNetAddr(fields[2], ipv6)
		role := "outbound"
		if isLikelyListenOrServer(fields[3], remoteIP, remotePort) {
			role = "inbound"
		}
		return connectionMetadata{
			SrcIP:    localIP,
			SrcPort:  localPort,
			DstIP:    remoteIP,
			DstPort:  remotePort,
			Protocol: "tcp",
			Family:   family,
			Role:     role,
		}, true
	}
	return connectionMetadata{}, false
}

func parseProcNetAddr(raw string, ipv6 bool) (string, int) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return "", 0
	}
	port64, _ := strconv.ParseInt(parts[1], 16, 32)
	if ipv6 {
		return parseIPv6Hex(parts[0]), int(port64)
	}
	return parseIPv4Hex(parts[0]), int(port64)
}

func parseIPv4Hex(raw string) string {
	if len(raw) != 8 {
		return ""
	}
	bytes := make([]byte, 4)
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseUint(raw[i*2:i*2+2], 16, 8)
		if err != nil {
			return ""
		}
		bytes[3-i] = byte(v)
	}
	return net.IP(bytes).String()
}

func parseIPv6Hex(raw string) string {
	if len(raw) != 32 {
		return ""
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != 16 {
		return ""
	}
	// /proc/net/tcp6 stores each 32-bit word little-endian.
	for i := 0; i < 16; i += 4 {
		decoded[i], decoded[i+3] = decoded[i+3], decoded[i]
		decoded[i+1], decoded[i+2] = decoded[i+2], decoded[i+1]
	}
	return net.IP(decoded).String()
}

func isLikelyListenOrServer(state, remoteIP string, remotePort int) bool {
	return state == "0A" || remotePort == 0 || remoteIP == "0.0.0.0" || remoteIP == "::"
}
