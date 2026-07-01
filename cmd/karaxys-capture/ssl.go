package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Karaxys/ebpf_tracer/pkg/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type sslUprobe struct {
	symbol string
	prog   *ebpf.Program
	ret    bool
}

func sslProbes(objs *bpf.Objects) []sslUprobe {
	return []sslUprobe{
		{"SSL_write", objs.ProbeEntrySSL_write, false},
		{"SSL_write", objs.ProbeRetSSL_write, true},
		{"SSL_read", objs.ProbeEntrySSL_read, false},
		{"SSL_read", objs.ProbeRetSSL_read, true},
		{"SSL_write_ex", objs.ProbeEntrySSL_writeEx, false},
		{"SSL_write_ex", objs.ProbeRetSSL_writeEx, true},
		{"SSL_read_ex", objs.ProbeEntrySSL_readEx, false},
		{"SSL_read_ex", objs.ProbeRetSSL_readEx, true},
	}
}

type sslAttacher struct {
	objs  *bpf.Objects
	mu    sync.Mutex
	seen  map[string]bool
	links []link.Link
}

func newSSLAttacher(objs *bpf.Objects) *sslAttacher {
	return &sslAttacher{objs: objs, seen: make(map[string]bool)}
}

func (a *sslAttacher) run(interval time.Duration, stop <-chan struct{}) {
	a.scanAndAttach()
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
			a.scanAndAttach()
		}
	}
}

func (a *sslAttacher) scanAndAttach() {
	for _, sslPath := range discoverLibssl() {
		id := fileIdentity(sslPath)
		a.mu.Lock()
		if a.seen[id] {
			a.mu.Unlock()
			continue
		}
		a.seen[id] = true
		a.mu.Unlock()

		ex, err := link.OpenExecutable(sslPath)
		if err != nil {
			continue
		}
		attached := 0
		for _, p := range sslProbes(a.objs) {
			if p.prog == nil {
				continue
			}
			var l link.Link
			if p.ret {
				l, err = ex.Uretprobe(p.symbol, p.prog, nil)
			} else {
				l, err = ex.Uprobe(p.symbol, p.prog, nil)
			}
			if err != nil {
				continue
			}
			a.mu.Lock()
			a.links = append(a.links, l)
			a.mu.Unlock()
			attached++
		}
		if attached > 0 {
			log.Printf("attached TLS uprobes (%d) on %s", attached, sslPath)
		}
	}
}

func (a *sslAttacher) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, l := range a.links {
		_ = l.Close()
	}
	a.links = nil
}

// discoverLibssl returns host-accessible libssl paths for every process that maps
// one, deduplicated by file identity.
func discoverLibssl() []string {
	seen := make(map[string]string)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		path := scanProcMapsForLibssl(pid)
		if path == "" {
			continue
		}
		if _, exists := seen[path]; !exists {
			seen[path] = ""
		}
	}
	out := make([]string, 0, len(seen))
	for path := range seen {
		out = append(out, path)
	}
	return out
}

func scanProcMapsForLibssl(pid int) string {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return ""
	}
	defer f.Close()

	root := fmt.Sprintf("/proc/%d/root", pid)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		slash := strings.IndexByte(line, '/')
		if slash < 0 {
			continue
		}
		path := line[slash:]
		if strings.Contains(filepath.Base(path), "libssl.so") {
			return hostAccessiblePath(root, path)
		}
	}
	return ""
}

// hostAccessiblePath resolves a library path that may live inside a container's
// mount namespace, preferring the direct path and falling back to /proc/<pid>/root.
func hostAccessiblePath(root, path string) string {
	if _, err := os.Stat(path); err == nil {
		return path
	}
	candidate := filepath.Join(root, path)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return ""
}

func fileIdentity(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return path
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d", st.Dev, st.Ino)
	}
	return path
}
