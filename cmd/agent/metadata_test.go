package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMetadataResolverCacheUsesFDGeneration(t *testing.T) {
	resolver := newMetadataResolver(time.Minute)
	now := time.Now()
	keyGenerationOne := flowKey{pid: 100, fd: 7, generation: 1}
	keyGenerationTwo := flowKey{pid: 100, fd: 7, generation: 2}

	resolver.cache[keyGenerationOne] = metadataCacheEntry{
		conn:      connectionMetadata{SrcPort: 8080},
		ok:        true,
		checkedAt: now,
	}
	resolver.cache[keyGenerationTwo] = metadataCacheEntry{
		conn:      connectionMetadata{SrcPort: 9090},
		ok:        true,
		checkedAt: now,
	}

	conn, _, _, ok := resolver.resolve(100, 7, 1)
	if !ok {
		t.Fatalf("expected cached generation 1 metadata")
	}
	if conn.SrcPort != 8080 {
		t.Fatalf("generation 1 src port = %d, want 8080", conn.SrcPort)
	}

	conn, _, _, ok = resolver.resolve(100, 7, 2)
	if !ok {
		t.Fatalf("expected cached generation 2 metadata")
	}
	if conn.SrcPort != 9090 {
		t.Fatalf("generation 2 src port = %d, want 9090", conn.SrcPort)
	}
}

func TestExtractContainerIdentityDockerSystemdCgroup(t *testing.T) {
	containerID := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	cgroup := "0::/system.slice/docker-" + containerID + ".scope"

	identity := extractContainerIdentity(cgroup)

	if identity.ID != containerID {
		t.Fatalf("container id = %q, want %q", identity.ID, containerID)
	}
	if identity.Runtime != "docker" {
		t.Fatalf("runtime = %q, want docker", identity.Runtime)
	}
	if identity.PodUID != "" {
		t.Fatalf("pod uid = %q, want empty", identity.PodUID)
	}
}

func TestExtractContainerIdentityKubernetesContainerdCgroup(t *testing.T) {
	containerID := "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
	podUID := "6d52cb1e-2f41-42db-a789-61f040d88701"
	cgroup := "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod6d52cb1e_2f41_42db_a789_61f040d88701.slice/cri-containerd-" + containerID + ".scope"

	identity := extractContainerIdentity(cgroup)

	if identity.ID != containerID {
		t.Fatalf("container id = %q, want %q", identity.ID, containerID)
	}
	if identity.Runtime != "containerd" {
		t.Fatalf("runtime = %q, want containerd", identity.Runtime)
	}
	if identity.PodUID != podUID {
		t.Fatalf("pod uid = %q, want %q", identity.PodUID, podUID)
	}
}

func TestExtractContainerIdentityKubernetesCRIOCgroup(t *testing.T) {
	containerID := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	podUID := "9a174cef-67f2-4704-99b0-e375e08d8a86"
	cgroup := "11:memory:/kubepods/besteffort/pod" + podUID + "/crio-" + containerID + ".scope"

	identity := extractContainerIdentity(cgroup)

	if identity.ID != containerID {
		t.Fatalf("container id = %q, want %q", identity.ID, containerID)
	}
	if identity.Runtime != "cri-o" {
		t.Fatalf("runtime = %q, want cri-o", identity.Runtime)
	}
	if identity.PodUID != podUID {
		t.Fatalf("pod uid = %q, want %q", identity.PodUID, podUID)
	}
}

func TestDecodeKubernetesPodMetadata(t *testing.T) {
	payload := `{
		"items": [
			{
				"metadata": {
					"uid": "6d52cb1e-2f41-42db-a789-61f040d88701",
					"name": "payments-api-77c8ccf7f5-x9sl7",
					"namespace": "production"
				},
				"spec": {
					"nodeName": "ip-10-0-12-54.ec2.internal"
				}
			}
		]
	}`

	metadata, ok := decodeKubernetesPodMetadata(json.NewDecoder(strings.NewReader(payload)), "6d52cb1e-2f41-42db-a789-61f040d88701")
	if !ok {
		t.Fatalf("expected Kubernetes metadata")
	}
	if metadata.Pod != "payments-api-77c8ccf7f5-x9sl7" || metadata.Namespace != "production" || metadata.Node != "ip-10-0-12-54.ec2.internal" {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
}
