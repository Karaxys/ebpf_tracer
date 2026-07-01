package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	containerMetadataTTL     = 5 * time.Minute
	externalMetadataTimeout  = 500 * time.Millisecond
	defaultDockerSocketPath  = "/var/run/docker.sock"
	serviceAccountTokenPath  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	serviceAccountCACertPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

var (
	containerRuntimeIDPattern = regexp.MustCompile(`(?i)(docker|cri-containerd|crio|libpod)-([a-f0-9]{64})(?:\.scope)?`)
	containerIDPattern        = regexp.MustCompile(`(?i)([a-f0-9]{64})`)
	kubernetesPodUIDPattern   = regexp.MustCompile(`(?i)pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})`)
)

// ── Port set ──────────────────────────────────────────────────────────────────

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

// parsePIDList parses a comma-separated list of PIDs. Empty input yields nil
// (meaning all-pids mode); blanks are skipped.
func parsePIDList(raw string) ([]uint32, error) {
	var pids []uint32
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		pid, err := strconv.ParseUint(part, 10, 32)
		if err != nil || pid == 0 {
			return nil, fmt.Errorf("invalid pid %q", part)
		}
		pids = append(pids, uint32(pid))
	}
	return pids, nil
}

// portFromURL extracts the TCP port from a URL, defaulting to the well-known
// port for the scheme when none is explicit. Returns 0 if it cannot be parsed.
func portFromURL(raw string) int {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return 0
	}
	if p := u.Port(); p != "" {
		port, err := strconv.Atoi(p)
		if err != nil {
			return 0
		}
		return port
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return 80
	case "https":
		return 443
	}
	return 0
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

func clonePortSet(s portSet) portSet {
	out := make(portSet, len(s))
	for port := range s {
		out[port] = struct{}{}
	}
	return out
}

// ── Flow filter ───────────────────────────────────────────────────────────────

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

func (f *flowFilter) allow(event CaptureEvent, metadataOK bool) bool {
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
		// A resolved connection that fails the port/role policy is a stable
		// denial — safe to cache.
		f.remember(key, flowDecisionDeny, now)
		return false
	}
	if event.EventType == eventTypeData && isLikelyHTTPPayload(event.Payload) {
		f.remember(key, flowDecisionAllow, now)
		return true
	}
	// No metadata yet and this particular chunk does not start with an HTTP
	// preamble. This is NOT a stable decision: the same connection may carry a
	// well-formed request or response in a later chunk (partial reads, response
	// after a non-HTTP-looking first segment). Caching DENY here would poison the
	// connection and suppress its real HTTP traffic, so we drop only this chunk.
	return false
}

func (f *flowFilter) connectionAllowed(conn ConnectionMetadata) bool {
	f.mu.Lock()
	targetPorts := clonePortSet(f.targetPorts)
	ignorePorts := clonePortSet(f.ignorePorts)
	captureInbound := f.captureInbound
	captureOutbound := f.captureOutbound
	f.mu.Unlock()

	if ignorePorts.matchesAny(conn.SrcPort, conn.DstPort) {
		return false
	}
	if conn.Role == "inbound" && !captureInbound {
		return false
	}
	if conn.Role == "outbound" && !captureOutbound {
		return false
	}
	if len(targetPorts) == 0 {
		return true
	}
	return targetPorts.matchesAny(conn.SrcPort, conn.DstPort)
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

// ── Metadata resolver ─────────────────────────────────────────────────────────

type metadataResolver struct {
	mu    sync.Mutex
	cache map[flowKey]metadataCacheEntry
	ttl   time.Duration
}

type metadataCacheEntry struct {
	conn      ConnectionMetadata
	process   ProcessMetadata
	container ContainerMetadata
	ok        bool
	checkedAt time.Time
}

type metadataSource uint8

const (
	metadataSourceNone metadataSource = iota
	metadataSourceCache
	metadataSourceProc
)

func newMetadataResolver(ttl time.Duration) *metadataResolver {
	return &metadataResolver{cache: make(map[flowKey]metadataCacheEntry), ttl: ttl}
}

func (r *metadataResolver) resolveWithSource(pid, fd, generation uint32) (ConnectionMetadata, ProcessMetadata, ContainerMetadata, bool, metadataSource) {
	now := time.Now()
	key := flowKey{pid: pid, fd: fd, generation: generation}

	var cachedProc ProcessMetadata
	var cachedContainer ContainerMetadata
	var hasFreshCache bool

	r.mu.Lock()
	if entry, ok := r.cache[key]; ok && now.Sub(entry.checkedAt) < r.ttl {
		if entry.ok {
			r.mu.Unlock()
			return entry.conn, entry.process, entry.container, true, metadataSourceCache
		}
		cachedProc = entry.process
		cachedContainer = entry.container
		hasFreshCache = true
	}
	r.mu.Unlock()

	conn, ok := resolveConnection(pid, fd)
	proc := cachedProc
	container := cachedContainer
	if !hasFreshCache {
		proc = resolveProcess(pid)
		container = resolveContainer(pid)
	}

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

	if ok {
		return conn, proc, container, true, metadataSourceProc
	}
	return conn, proc, container, false, metadataSourceNone
}

func (r *metadataResolver) remember(pid, fd, generation uint32, conn ConnectionMetadata, proc ProcessMetadata, container ContainerMetadata) {
	if r == nil || conn.Protocol == "" {
		return
	}
	key := flowKey{pid: pid, fd: fd, generation: generation}
	now := time.Now()
	r.mu.Lock()
	if entry, ok := r.cache[key]; ok && entry.ok && now.Sub(entry.checkedAt) < r.ttl {
		r.mu.Unlock()
		return
	}
	r.cache[key] = metadataCacheEntry{conn: conn, process: proc, container: container, ok: true, checkedAt: now}
	r.mu.Unlock()
}

func (r *metadataResolver) forget(pid, fd, generation uint32) {
	if r == nil {
		return
	}
	key := flowKey{pid: pid, fd: fd, generation: generation}
	r.mu.Lock()
	delete(r.cache, key)
	r.mu.Unlock()
}

// ── /proc-based resolution ────────────────────────────────────────────────────

func resolveProcess(pid uint32) ProcessMetadata {
	pidStr := strconv.FormatUint(uint64(pid), 10)
	nameBytes, _ := os.ReadFile(filepath.Join("/proc", pidStr, "comm"))
	exe, _ := os.Readlink(filepath.Join("/proc", pidStr, "exe"))
	return ProcessMetadata{PID: pid, Name: strings.TrimSpace(string(nameBytes)), Exe: exe}
}

func resolveConnection(pid, fd uint32) (ConnectionMetadata, bool) {
	inode, err := socketInode(pid, fd)
	if err != nil || inode == "" {
		return ConnectionMetadata{}, false
	}
	if conn, ok := findTCPConnection(pid, inode, false); ok {
		return conn, true
	}
	if conn, ok := findTCPConnection(pid, inode, true); ok {
		return conn, true
	}
	return ConnectionMetadata{}, false
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

func findTCPConnection(pid uint32, inode string, ipv6 bool) (ConnectionMetadata, bool) {
	path := fmt.Sprintf("/proc/%d/net/tcp", pid)
	family := "ipv4"
	if ipv6 {
		path = fmt.Sprintf("/proc/%d/net/tcp6", pid)
		family = "ipv6"
	}

	f, err := os.Open(path)
	if err != nil {
		return ConnectionMetadata{}, false
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
		return ConnectionMetadata{
			SrcIP: localIP, SrcPort: localPort,
			DstIP: remoteIP, DstPort: remotePort,
			Protocol: "tcp", Family: family, Role: role,
		}, true
	}
	return ConnectionMetadata{}, false
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
	b := make([]byte, 4)
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseUint(raw[i*2:i*2+2], 16, 8)
		if err != nil {
			return ""
		}
		b[3-i] = byte(v)
	}
	return net.IP(b).String()
}

func parseIPv6Hex(raw string) string {
	if len(raw) != 32 {
		return ""
	}
	b := make([]byte, 16)
	for group := 0; group < 4; group++ {
		chunk := raw[group*8 : (group+1)*8]
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(chunk[i*2:i*2+2], 16, 8)
			if err != nil {
				return ""
			}
			b[group*4+(3-i)] = byte(v)
		}
	}
	return net.IP(b).String()
}

func isLikelyListenOrServer(state, remoteIP string, remotePort int) bool {
	if state == "0A" {
		return true
	}
	if remotePort == 0 && (remoteIP == "0.0.0.0" || remoteIP == "::" || remoteIP == "") {
		return true
	}
	return false
}

func isLikelyHTTPPayload(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	if len(payload) > 64 {
		payload = payload[:64]
	}
	return classifyPayload(payload) != payloadUnknown
}

// ── Container metadata ────────────────────────────────────────────────────────

type containerIdentity struct {
	ID      string
	Runtime string
	PodUID  string
}

type containerMetadataCacheEntry struct {
	metadata  ContainerMetadata
	checkedAt time.Time
}

var containerMetadataCache = struct {
	sync.Mutex
	values map[string]containerMetadataCacheEntry
}{
	values: make(map[string]containerMetadataCacheEntry),
}

func resolveContainer(pid uint32) ContainerMetadata {
	pidStr := strconv.FormatUint(uint64(pid), 10)
	cgroupBytes, err := os.ReadFile(filepath.Join("/proc", pidStr, "cgroup"))
	if err != nil {
		return ContainerMetadata{}
	}

	identity := extractContainerIdentity(string(cgroupBytes))
	metadata := ContainerMetadata{
		ID:      identity.ID,
		Runtime: identity.Runtime,
		PodUID:  identity.PodUID,
		Node:    firstNonEmptyEnv("KARAXYS_NODE_NAME", "NODE_NAME"),
	}
	if identity.ID == "" && identity.PodUID == "" {
		return metadata
	}

	cacheKey := identity.Runtime + ":" + identity.ID + ":" + identity.PodUID
	if cached, ok := loadContainerMetadataCache(cacheKey); ok {
		if cached.Node == "" {
			cached.Node = metadata.Node
		}
		return cached
	}

	if identity.ID != "" {
		if dockerMeta, ok := resolveDockerContainerMetadata(identity.ID); ok {
			mergeContainerMetadata(&metadata, dockerMeta)
		}
	}
	if identity.PodUID != "" {
		if podMeta, ok := resolveKubernetesPodMetadata(identity.PodUID); ok {
			mergeContainerMetadata(&metadata, podMeta)
		}
	}

	storeContainerMetadataCache(cacheKey, metadata)
	return metadata
}

func extractContainerIdentity(cgroup string) containerIdentity {
	identity := containerIdentity{
		Runtime: containerRuntimeFromCgroup(cgroup),
		PodUID:  extractKubernetesPodUID(cgroup),
	}
	if match := containerRuntimeIDPattern.FindStringSubmatch(cgroup); len(match) == 3 {
		identity.Runtime = normalizeContainerRuntime(match[1])
		identity.ID = strings.ToLower(match[2])
		return identity
	}
	if match := containerIDPattern.FindStringSubmatch(cgroup); len(match) == 2 {
		identity.ID = strings.ToLower(match[1])
	}
	return identity
}

func extractKubernetesPodUID(cgroup string) string {
	match := kubernetesPodUIDPattern.FindStringSubmatch(cgroup)
	if len(match) != 2 {
		return ""
	}
	return strings.ToLower(strings.ReplaceAll(match[1], "_", "-"))
}

func containerRuntimeFromCgroup(cgroup string) string {
	lower := strings.ToLower(cgroup)
	switch {
	case strings.Contains(lower, "cri-containerd"):
		return "containerd"
	case strings.Contains(lower, "crio"):
		return "cri-o"
	case strings.Contains(lower, "libpod"):
		return "podman"
	case strings.Contains(lower, "docker"):
		return "docker"
	default:
		return ""
	}
}

func normalizeContainerRuntime(runtime string) string {
	switch strings.ToLower(runtime) {
	case "cri-containerd":
		return "containerd"
	case "crio":
		return "cri-o"
	case "libpod":
		return "podman"
	default:
		return strings.ToLower(runtime)
	}
}

func loadContainerMetadataCache(key string) (ContainerMetadata, bool) {
	if key == "::" {
		return ContainerMetadata{}, false
	}
	now := time.Now()
	containerMetadataCache.Lock()
	defer containerMetadataCache.Unlock()
	entry, ok := containerMetadataCache.values[key]
	if !ok {
		return ContainerMetadata{}, false
	}
	if now.Sub(entry.checkedAt) >= containerMetadataTTL {
		delete(containerMetadataCache.values, key)
		return ContainerMetadata{}, false
	}
	return entry.metadata, true
}

func storeContainerMetadataCache(key string, metadata ContainerMetadata) {
	if key == "::" {
		return
	}
	now := time.Now()
	containerMetadataCache.Lock()
	containerMetadataCache.values[key] = containerMetadataCacheEntry{metadata: metadata, checkedAt: now}
	if len(containerMetadataCache.values) > 8192 {
		cutoff := now.Add(-2 * containerMetadataTTL)
		for k, entry := range containerMetadataCache.values {
			if entry.checkedAt.Before(cutoff) {
				delete(containerMetadataCache.values, k)
			}
		}
	}
	containerMetadataCache.Unlock()
}

func resolveDockerContainerMetadata(containerID string) (ContainerMetadata, bool) {
	socketPath := firstNonEmptyEnv("KARAXYS_DOCKER_SOCKET", "DOCKER_HOST_UNIX")
	if socketPath == "" {
		socketPath = defaultDockerSocketPath
	}
	if trimmed, ok := strings.CutPrefix(socketPath, "unix://"); ok {
		socketPath = trimmed
	}
	if _, err := os.Stat(socketPath); err != nil {
		return ContainerMetadata{}, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), externalMetadataTimeout)
	defer cancel()

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/"+url.PathEscape(containerID)+"/json", nil)
	if err != nil {
		return ContainerMetadata{}, false
	}
	resp, err := client.Do(req)
	if err != nil {
		return ContainerMetadata{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ContainerMetadata{}, false
	}

	var body struct {
		Name   string `json:"Name"`
		Config struct {
			Image string `json:"Image"`
		} `json:"Config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return ContainerMetadata{}, false
	}
	return ContainerMetadata{
		ID:      containerID,
		Name:    strings.TrimPrefix(body.Name, "/"),
		Image:   body.Config.Image,
		Runtime: "docker",
	}, true
}

func resolveKubernetesPodMetadata(podUID string) (ContainerMetadata, bool) {
	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	if host == "" {
		return ContainerMetadata{}, false
	}
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS"))
	if port == "" {
		port = strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	}
	if port == "" {
		port = "443"
	}

	tokenBytes, err := os.ReadFile(serviceAccountTokenPath)
	if err != nil || len(strings.TrimSpace(string(tokenBytes))) == 0 {
		return ContainerMetadata{}, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), externalMetadataTimeout)
	defer cancel()

	values := url.Values{}
	values.Set("fieldSelector", "metadata.uid="+podUID)
	values.Set("limit", "1")
	reqURL := "https://" + net.JoinHostPort(host, port) + "/api/v1/pods?" + values.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return ContainerMetadata{}, false
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tokenBytes)))
	req.Header.Set("Accept", "application/json")

	transport := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   kubernetesTLSConfig(),
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		return ContainerMetadata{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ContainerMetadata{}, false
	}

	var body struct {
		Items []struct {
			Metadata struct {
				UID       string `json:"uid"`
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Spec struct {
				NodeName string `json:"nodeName"`
			} `json:"spec"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return ContainerMetadata{}, false
	}
	for _, item := range body.Items {
		if !strings.EqualFold(item.Metadata.UID, podUID) {
			continue
		}
		return ContainerMetadata{
			PodUID:    strings.ToLower(item.Metadata.UID),
			Pod:       item.Metadata.Name,
			Namespace: item.Metadata.Namespace,
			Node:      item.Spec.NodeName,
		}, true
	}
	return ContainerMetadata{}, false
}

func kubernetesTLSConfig() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	caBytes, err := os.ReadFile(serviceAccountCACertPath)
	if err != nil {
		return cfg
	}
	pool := x509.NewCertPool()
	if pool.AppendCertsFromPEM(caBytes) {
		cfg.RootCAs = pool
	}
	return cfg
}

func mergeContainerMetadata(dst *ContainerMetadata, src ContainerMetadata) {
	if dst.ID == "" {
		dst.ID = src.ID
	}
	if dst.Name == "" {
		dst.Name = src.Name
	}
	if dst.Image == "" {
		dst.Image = src.Image
	}
	if dst.Namespace == "" {
		dst.Namespace = src.Namespace
	}
	if dst.Pod == "" {
		dst.Pod = src.Pod
	}
	if dst.Node == "" {
		dst.Node = src.Node
	}
	if dst.Runtime == "" {
		dst.Runtime = src.Runtime
	}
	if dst.PodUID == "" {
		dst.PodUID = src.PodUID
	}
}

func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}
