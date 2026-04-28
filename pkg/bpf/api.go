package bpf

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Objects exposes generated BPF objects to external packages.
type Objects = bpfObjects

// ApiEvent mirrors struct api_event in bpf/tracer.bpf.c.
type ApiEvent struct {
	Timestamp  uint64
	Pid        uint32
	Tid        uint32
	Fd         uint32
	Generation uint32
	Seq        uint32
	Size       uint32
	ChunkIndex uint16
	ChunkCount uint16
	Direction  uint8
	EventType  uint8
	Flags      uint8
	Pad        uint8
	Payload    [4096]byte
}

// SetRlimit removes the memlock rlimit needed to load eBPF objects.
func SetRlimit() error {
	return rlimit.RemoveMemlock()
}

// LoadObjects loads generated programs and maps into the kernel.
func LoadObjects(obj *Objects, opts *ebpf.CollectionOptions) error {
	return loadBpfObjects(obj, opts)
}
