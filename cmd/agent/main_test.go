package main

import (
	"testing"

	"github.com/Karaxys/ebpf_tracer/pkg/bpf"
)

func TestValidateKernelMaxPayloadSize(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		want    uint32
		wantErr bool
	}{
		{name: "minimum", size: 1, want: 1},
		{name: "default maximum", size: maxKernelPayloadSize, want: maxKernelPayloadSize},
		{name: "zero rejected", size: 0, wantErr: true},
		{name: "negative rejected", size: -1, wantErr: true},
		{name: "above maximum rejected", size: maxKernelPayloadSize + 1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateKernelMaxPayloadSize(tt.size)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestBoolToKernelConfig(t *testing.T) {
	if got := boolToKernelConfig(true); got != 1 {
		t.Fatalf("true encoded as %d, want 1", got)
	}
	if got := boolToKernelConfig(false); got != 0 {
		t.Fatalf("false encoded as %d, want 0", got)
	}
}

func TestKernelSocketTupleFromConnection(t *testing.T) {
	conn := connectionMetadata{
		SrcPort:  5000,
		DstPort:  43210,
		Protocol: "tcp",
		Family:   "ipv4",
		Role:     "inbound",
	}

	tuple, ok := kernelSocketTupleFromConnection(conn)
	if !ok {
		t.Fatalf("expected tuple")
	}
	if tuple.Family != kernelAFInet {
		t.Fatalf("family = %d, want %d", tuple.Family, kernelAFInet)
	}
	if tuple.LocalPort != 5000 || tuple.RemotePort != 43210 {
		t.Fatalf("unexpected ports: %+v", tuple)
	}
	if tuple.Role != socketRoleInbound {
		t.Fatalf("role = %d, want inbound", tuple.Role)
	}
	if tuple.Flags != socketTupleLocal|socketTupleRemote {
		t.Fatalf("flags = %d, want local|remote", tuple.Flags)
	}
}

func TestKernelSocketTupleFromConnectionRejectsIncompleteMetadata(t *testing.T) {
	tests := []connectionMetadata{
		{Protocol: "udp", Family: "ipv4", SrcPort: 53},
		{Protocol: "tcp", Family: "", SrcPort: 8080},
		{Protocol: "tcp", Family: "ipv4"},
		{Protocol: "tcp", Family: "ipv4", SrcPort: 70000},
	}

	for _, tt := range tests {
		if tuple, ok := kernelSocketTupleFromConnection(tt); ok {
			t.Fatalf("expected rejection for %+v, got %+v", tt, tuple)
		}
	}
}

func TestConnectionFromKernelTuple(t *testing.T) {
	event := bpf.ApiEvent{
		LocalPort:        8443,
		RemotePort:       51000,
		SocketFamily:     6,
		SocketRole:       socketRoleOutbound,
		SocketTupleFlags: socketTupleLocal | socketTupleRemote,
	}

	conn, ok := connectionFromKernelTuple(event)
	if !ok {
		t.Fatalf("expected connection metadata")
	}
	if conn.Protocol != "tcp" || conn.Family != "ipv6" || conn.Role != "outbound" {
		t.Fatalf("unexpected connection labels: %+v", conn)
	}
	if conn.SrcPort != 8443 || conn.DstPort != 51000 {
		t.Fatalf("unexpected ports: %+v", conn)
	}
}
