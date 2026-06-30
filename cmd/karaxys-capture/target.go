package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
)

// allPIDsTargetManager refreshes the kernel target_pids BPF map every interval
// so newly-spawned processes are captured without restarting the binary.
//
// The discovery source is pluggable: the default ("all-pids") mode enumerates
// every process so traffic on any port from any app is captured, while an
// opt-in scoped mode supplies only a subset (specific PIDs and, optionally,
// their descendants). The refresh/diff/run machinery is identical in both modes.
type allPIDsTargetManager struct {
	bpfMap   *ebpf.Map
	maxPIDs  int
	discover func() ([]uint32, error)
	mode     string
	mu       sync.Mutex
	active   map[uint32]struct{}
}

func newAllPIDsTargetManager(bpfMap *ebpf.Map, maxPIDs int) *allPIDsTargetManager {
	return &allPIDsTargetManager{
		bpfMap:   bpfMap,
		maxPIDs:  maxPIDs,
		discover: discoverAllPIDs,
		mode:     "all-pids",
		active:   make(map[uint32]struct{}),
	}
}

// newScopedTargetManager traces only the given PIDs (and, when pidTree is set,
// their live descendants). This is purely opt-in; the default capture path uses
// newAllPIDsTargetManager and is unaffected.
func newScopedTargetManager(bpfMap *ebpf.Map, maxPIDs int, targetPIDs []uint32, pidTree bool) *allPIDsTargetManager {
	seed := append([]uint32(nil), targetPIDs...)
	mode := "pids"
	if pidTree {
		mode = "pid-tree"
	}
	return &allPIDsTargetManager{
		bpfMap:  bpfMap,
		maxPIDs: maxPIDs,
		discover: func() ([]uint32, error) {
			if pidTree {
				return discoverPIDTree(seed)
			}
			return livePIDs(seed), nil
		},
		mode:   mode,
		active: make(map[uint32]struct{}),
	}
}

func (m *allPIDsTargetManager) refresh() error {
	pids, err := m.discover()
	if err != nil {
		return fmt.Errorf("discover target PIDs (%s): %w", m.mode, err)
	}
	if m.maxPIDs > 0 && len(pids) > m.maxPIDs {
		return fmt.Errorf("PID count %d exceeds --all-pids-max=%d", len(pids), m.maxPIDs)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	next := make(map[uint32]struct{}, len(pids))
	for _, pid := range pids {
		next[pid] = struct{}{}
		if _, exists := m.active[pid]; !exists {
			flag := uint8(1)
			if err := m.bpfMap.Put(&pid, &flag); err != nil {
				return fmt.Errorf("add target pid %d: %w", pid, err)
			}
		}
	}
	for pid := range m.active {
		if _, stillActive := next[pid]; !stillActive {
			_ = m.bpfMap.Delete(&pid)
		}
	}
	m.active = next
	return nil
}

func (m *allPIDsTargetManager) run(interval time.Duration, stop <-chan struct{}) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if err := m.refresh(); err != nil {
				log.Printf("target refresh failed: %v", err)
			}
		}
	}
}

// ── PID discovery ─────────────────────────────────────────────────────────────

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

// livePIDs returns the subset of the given PIDs that currently exist in /proc.
func livePIDs(pids []uint32) []uint32 {
	seen := make(map[uint32]struct{}, len(pids))
	for _, pid := range pids {
		if pid == 0 {
			continue
		}
		if _, err := os.Stat(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10))); err == nil {
			seen[pid] = struct{}{}
		}
	}
	return sortedPIDs(seen)
}

// discoverPIDTree returns the seed PIDs plus all of their live descendants,
// resolved via each process's PPid in /proc/<pid>/stat.
func discoverPIDTree(seed []uint32) ([]uint32, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	parent := make(map[uint32]uint32) // pid -> ppid
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil || pid64 == 0 {
			continue
		}
		pid := uint32(pid64)
		if ppid, ok := parentPID(pid); ok {
			parent[pid] = ppid
		}
	}

	targets := make(map[uint32]struct{}, len(seed))
	for _, pid := range seed {
		if pid != 0 {
			targets[pid] = struct{}{}
		}
	}
	// Walk each process's ancestry; if any ancestor is a seed, include it.
	for pid := range parent {
		cur := pid
		for hops := 0; hops < 1024; hops++ {
			if _, ok := targets[cur]; ok {
				targets[pid] = struct{}{}
				break
			}
			next, ok := parent[cur]
			if !ok || next == cur || next == 0 {
				break
			}
			cur = next
		}
	}
	return livePIDs(mapKeys(targets)), nil
}

func parentPID(pid uint32) (uint32, bool) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "stat"))
	if err != nil {
		return 0, false
	}
	// /proc/<pid>/stat: "pid (comm) state ppid ...". comm may contain spaces and
	// parens, so parse from the last ')' to avoid splitting inside it.
	close := strings.LastIndexByte(string(raw), ')')
	if close < 0 {
		return 0, false
	}
	fields := strings.Fields(string(raw)[close+1:])
	if len(fields) < 2 { // [state, ppid, ...]
		return 0, false
	}
	ppid64, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(ppid64), true
}

func mapKeys(set map[uint32]struct{}) []uint32 {
	out := make([]uint32, 0, len(set))
	for pid := range set {
		out = append(out, pid)
	}
	return out
}

func sortedPIDs(set map[uint32]struct{}) []uint32 {
	pids := make([]uint32, 0, len(set))
	for pid := range set {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	return pids
}

// cgroupIDForPID resolves the cgroup v2 inode ID for the given PID.
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
