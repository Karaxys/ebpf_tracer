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
type allPIDsTargetManager struct {
	bpfMap  *ebpf.Map
	maxPIDs int
	mu      sync.Mutex
	active  map[uint32]struct{}
}

func newAllPIDsTargetManager(bpfMap *ebpf.Map, maxPIDs int) *allPIDsTargetManager {
	return &allPIDsTargetManager{
		bpfMap:  bpfMap,
		maxPIDs: maxPIDs,
		active:  make(map[uint32]struct{}),
	}
}

func (m *allPIDsTargetManager) refresh() error {
	pids, err := discoverAllPIDs()
	if err != nil {
		return fmt.Errorf("discover all PIDs: %w", err)
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
