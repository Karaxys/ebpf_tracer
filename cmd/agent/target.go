package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
)

type targetMode string

const (
	targetModePID       targetMode = "pid"
	targetModePIDTree   targetMode = "pid-tree"
	targetModeContainer targetMode = "container"
	targetModeAllPIDs   targetMode = "all-pids"
)

type targetConfig struct {
	mode            targetMode
	pid             int
	container       string
	refreshInterval time.Duration
	allowAllPIDs    bool
	maxPIDs         int
	cgroupFilter    bool
}

type targetManager struct {
	cfg          targetConfig
	bpfMap       *ebpf.Map
	cgroupMap    *ebpf.Map
	mu           sync.Mutex
	active       map[uint32]struct{}
	activeGroups map[uint64]struct{}
	lastLabel    string
}

func newTargetManager(cfg targetConfig, bpfMap *ebpf.Map, cgroupMap *ebpf.Map) *targetManager {
	return &targetManager{
		cfg:          cfg,
		bpfMap:       bpfMap,
		cgroupMap:    cgroupMap,
		active:       make(map[uint32]struct{}),
		activeGroups: make(map[uint64]struct{}),
	}
}

func parseTargetMode(raw string) (targetMode, error) {
	switch targetMode(strings.TrimSpace(raw)) {
	case targetModePID, targetModePIDTree, targetModeContainer, targetModeAllPIDs:
		return targetMode(raw), nil
	default:
		return "", fmt.Errorf("unsupported target mode %q", raw)
	}
}

func (m *targetManager) refresh() ([]uint32, error) {
	pids, label, err := resolveTargetPIDs(m.cfg)
	if err != nil {
		return nil, err
	}
	if len(pids) == 0 {
		return nil, fmt.Errorf("target resolution returned no PIDs for mode=%s", m.cfg.mode)
	}
	if m.cfg.mode == targetModeAllPIDs && m.cfg.maxPIDs > 0 && len(pids) > m.cfg.maxPIDs {
		return nil, fmt.Errorf("target resolution returned %d PIDs, exceeds -all-pids-max=%d", len(pids), m.cfg.maxPIDs)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	next := make(map[uint32]struct{}, len(pids))
	for _, pid := range pids {
		next[pid] = struct{}{}
		if _, exists := m.active[pid]; !exists {
			flag := uint8(1)
			if err := m.bpfMap.Put(&pid, &flag); err != nil {
				return nil, fmt.Errorf("add target pid %d: %w", pid, err)
			}
		}
	}

	for pid := range m.active {
		if _, stillActive := next[pid]; !stillActive {
			_ = m.bpfMap.Delete(&pid)
		}
	}

	changed := !samePIDSet(m.active, next) || label != m.lastLabel
	m.active = next
	m.lastLabel = label
	if err := m.refreshCgroupsLocked(pids); err != nil {
		return nil, err
	}

	if changed {
		log.Printf("target_refresh mode=%s label=%s active_pids=%v", m.cfg.mode, label, pids)
	}

	return pids, nil
}

func (m *targetManager) refreshCgroupsLocked(pids []uint32) error {
	if !m.cfg.cgroupFilter || m.cgroupMap == nil {
		return nil
	}
	next, err := discoverCgroupIDsForPIDs(pids)
	if err != nil {
		return err
	}
	for cgroupID := range next {
		if _, exists := m.activeGroups[cgroupID]; !exists {
			flag := uint8(1)
			if err := m.cgroupMap.Put(&cgroupID, &flag); err != nil {
				return fmt.Errorf("add cgroup id %d: %w", cgroupID, err)
			}
		}
	}
	for cgroupID := range m.activeGroups {
		if _, stillActive := next[cgroupID]; !stillActive {
			_ = m.cgroupMap.Delete(&cgroupID)
		}
	}
	m.activeGroups = next
	return nil
}

func (m *targetManager) run(stop <-chan struct{}) {
	if m.cfg.refreshInterval <= 0 {
		return
	}

	ticker := time.NewTicker(m.cfg.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if _, err := m.refresh(); err != nil {
				log.Printf("target refresh failed: %v", err)
			}
		}
	}
}

func resolveTargetPIDs(cfg targetConfig) ([]uint32, string, error) {
	switch cfg.mode {
	case targetModePID:
		if cfg.pid <= 0 {
			return nil, "", fmt.Errorf("-pid must be provided for target-mode=pid")
		}
		return []uint32{uint32(cfg.pid)}, fmt.Sprintf("pid:%d", cfg.pid), nil
	case targetModePIDTree:
		if cfg.pid <= 0 {
			return nil, "", fmt.Errorf("-pid must be provided for target-mode=pid-tree")
		}
		pids, err := discoverPIDTree(uint32(cfg.pid))
		return pids, fmt.Sprintf("pid-tree:%d", cfg.pid), err
	case targetModeContainer:
		if strings.TrimSpace(cfg.container) == "" {
			return nil, "", fmt.Errorf("-container must be provided for target-mode=container")
		}
		pids, err := discoverContainerPIDs(cfg.container)
		return pids, fmt.Sprintf("container:%s", cfg.container), err
	case targetModeAllPIDs:
		if !cfg.allowAllPIDs {
			return nil, "", fmt.Errorf("target-mode=all-pids requires -allow-all-pids=true")
		}
		pids, err := discoverAllPIDs()
		return pids, "all-pids", err
	default:
		return nil, "", fmt.Errorf("unsupported target mode %q", cfg.mode)
	}
}

func discoverCgroupIDsForPIDs(pids []uint32) (map[uint64]struct{}, error) {
	ids := make(map[uint64]struct{})
	for _, pid := range pids {
		cgroupID, ok := cgroupIDForPID(pid)
		if ok {
			ids[cgroupID] = struct{}{}
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no cgroup v2 IDs resolved for %d PIDs", len(pids))
	}
	return ids, nil
}

func cgroupIDForPID(pid uint32) (uint64, bool) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "cgroup"))
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 || fields[0] != "0" {
			continue
		}
		cgroupPath := filepath.Clean("/" + strings.TrimPrefix(fields[2], "/"))
		fullPath := filepath.Join("/sys/fs/cgroup", cgroupPath)
		if !strings.HasPrefix(fullPath, "/sys/fs/cgroup") {
			return 0, false
		}
		info, err := os.Stat(fullPath)
		if err != nil {
			return 0, false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Ino == 0 {
			return 0, false
		}
		return stat.Ino, true
	}
	return 0, false
}

func discoverPIDTree(root uint32) ([]uint32, error) {
	children, err := processChildren()
	if err != nil {
		return nil, err
	}

	seen := map[uint32]struct{}{root: struct{}{}}
	queue := []uint32{root}
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		for _, child := range children[pid] {
			if _, ok := seen[child]; ok {
				continue
			}
			seen[child] = struct{}{}
			queue = append(queue, child)
		}
	}

	return sortedPIDs(seen), nil
}

func discoverAllPIDs() ([]uint32, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	seen := make(map[uint32]struct{})
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil || pid64 == 0 {
			continue
		}
		seen[uint32(pid64)] = struct{}{}
	}
	return sortedPIDs(seen), nil
}

func discoverContainerPIDs(container string) ([]uint32, error) {
	if pids, err := discoverContainerPIDsWithDocker(container); err == nil && len(pids) > 0 {
		return pids, nil
	}

	needle := strings.TrimSpace(container)
	if len(needle) > 12 {
		needle = needle[:12]
	}
	seen := make(map[uint32]struct{})
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil || pid64 == 0 {
			continue
		}
		pid := uint32(pid64)
		cgroup, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cgroup"))
		if err != nil {
			continue
		}
		if strings.Contains(string(cgroup), container) || strings.Contains(string(cgroup), needle) {
			seen[pid] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("container %q not found via docker or /proc cgroup scan", container)
	}
	return sortedPIDs(seen), nil
}

func discoverContainerPIDsWithDocker(container string) ([]uint32, error) {
	cmd := exec.Command("docker", "top", container, "-eo", "pid")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	seen := make(map[uint32]struct{})
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.EqualFold(line, "PID") {
			continue
		}
		pid64, err := strconv.ParseUint(line, 10, 32)
		if err != nil || pid64 == 0 {
			continue
		}
		seen[uint32(pid64)] = struct{}{}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("docker top returned no PIDs for %q", container)
	}
	return sortedPIDs(seen), nil
}

func processChildren() (map[uint32][]uint32, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	children := make(map[uint32][]uint32)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil || pid64 == 0 {
			continue
		}
		stat, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err != nil {
			continue
		}
		ppid, ok := parsePPIDFromStat(string(stat))
		if !ok || ppid == 0 {
			continue
		}
		children[ppid] = append(children[ppid], uint32(pid64))
	}
	return children, nil
}

func parsePPIDFromStat(stat string) (uint32, bool) {
	end := strings.LastIndex(stat, ")")
	if end < 0 || end+2 >= len(stat) {
		return 0, false
	}
	fields := strings.Fields(stat[end+2:])
	if len(fields) < 2 {
		return 0, false
	}
	ppid64, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(ppid64), true
}

func sortedPIDs(set map[uint32]struct{}) []uint32 {
	pids := make([]uint32, 0, len(set))
	for pid := range set {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	return pids
}

func samePIDSet(a, b map[uint32]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for pid := range a {
		if _, ok := b[pid]; !ok {
			return false
		}
	}
	return true
}
