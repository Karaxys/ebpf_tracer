package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang bpf ../../bpf/tracer.bpf.c -- -I../../bpf/headers -I/usr/include -D__TARGET_ARCH_x86 -Wno-missing-declarations
