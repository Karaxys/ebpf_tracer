package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang bpf ../../bpf/tracer.bpf.c -- -I../../bpf/headers -I/usr/include -Wno-missing-declarations
