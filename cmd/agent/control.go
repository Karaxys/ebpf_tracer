package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Karaxys/ebpf_tracer/pkg/bpf"
)

type agentControlClient struct {
	baseURL string
	token   string
	client  *http.Client
}

type agentRemoteConfig struct {
	SchemaVersion            string `json:"schema_version"`
	ConfigVersion            string `json:"config_version"`
	PollIntervalSeconds      int    `json:"poll_interval_seconds"`
	HeartbeatIntervalSeconds int    `json:"heartbeat_interval_seconds"`
	TargetPorts              []int  `json:"target_ports"`
	IgnorePorts              []int  `json:"ignore_ports"`
	CaptureInbound           bool   `json:"capture_inbound"`
	CaptureOutbound          bool   `json:"capture_outbound"`
	CaptureReadSyscalls      bool   `json:"capture_read_syscalls"`
	CaptureWriteSyscalls     bool   `json:"capture_write_syscalls"`
	AllowNonSocketFDs        bool   `json:"allow_non_socket_fds"`
	MaxPayloadSize           int    `json:"max_payload_size"`
}

type agentHeartbeatPayload struct {
	AgentVersion string                 `json:"agent_version,omitempty"`
	TargetMode   string                 `json:"target_mode,omitempty"`
	Stats        map[string]interface{} `json:"stats,omitempty"`
}

func newAgentControlClient(baseURL, token string, timeout time.Duration) *agentControlClient {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	token = strings.TrimSpace(token)
	if baseURL == "" || token == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &agentControlClient{
		baseURL: baseURL,
		token:   token,
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *agentControlClient) getConfig() (agentRemoteConfig, error) {
	var cfg agentRemoteConfig
	if c == nil {
		return cfg, fmt.Errorf("agent control client is not configured")
	}
	req, err := http.NewRequest(http.MethodGet, c.baseURL+"/agents/config", nil)
	if err != nil {
		return cfg, err
	}
	c.authorize(req)
	resp, err := c.client.Do(req)
	if err != nil {
		return cfg, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return cfg, controlStatusError(resp)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128*1024)).Decode(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *agentControlClient) heartbeat(payload agentHeartbeatPayload) error {
	if c == nil {
		return fmt.Errorf("agent control client is not configured")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/agents/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.authorize(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return controlStatusError(resp)
	}
	return nil
}

func (c *agentControlClient) authorize(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.token)
}

func controlStatusError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("backend control returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

func runAgentHeartbeat(stop <-chan struct{}, client *agentControlClient, interval time.Duration, targetMode string, stats *agentStats, queueDepth func() int) {
	if client == nil {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	send := func(reason string) {
		payload := agentHeartbeatPayload{
			TargetMode: targetMode,
			Stats: map[string]interface{}{
				"ring_records":      atomic.LoadUint64(&stats.ringRecords),
				"decoded_events":    atomic.LoadUint64(&stats.decodedEvents),
				"metadata_misses":   atomic.LoadUint64(&stats.metadataMisses),
				"truncated_events":  atomic.LoadUint64(&stats.truncatedEvents),
				"produce_attempts":  atomic.LoadUint64(&stats.produceAttempts),
				"produce_errors":    atomic.LoadUint64(&stats.produceErrors),
				"delivery_failures": atomic.LoadUint64(&stats.deliveryFailures),
			},
		}
		if queueDepth != nil {
			payload.Stats["local_queue_depth"] = queueDepth()
		}
		if err := client.heartbeat(payload); err != nil {
			log.Printf("agent heartbeat failed reason=%s err=%v", reason, err)
		}
	}

	send("startup")
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			send("shutdown")
			return
		case <-ticker.C:
			send("periodic")
		}
	}
}

func runAgentRemoteConfig(stop <-chan struct{}, client *agentControlClient, interval time.Duration, apply func(agentRemoteConfig) error) {
	if client == nil || apply == nil {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	var currentVersion string
	poll := func() time.Duration {
		cfg, err := client.getConfig()
		if err != nil {
			log.Printf("agent config poll failed: %v", err)
			return interval
		}
		if cfg.ConfigVersion != "" && cfg.ConfigVersion == currentVersion {
			return boundedPollInterval(cfg.PollIntervalSeconds, interval)
		}
		if err := apply(cfg); err != nil {
			log.Printf("agent config apply failed version=%s: %v", cfg.ConfigVersion, err)
			return interval
		}
		currentVersion = cfg.ConfigVersion
		log.Printf("agent config applied version=%s target_ports=%v ignore_ports=%v", cfg.ConfigVersion, cfg.TargetPorts, cfg.IgnorePorts)
		return boundedPollInterval(cfg.PollIntervalSeconds, interval)
	}

	next := poll()
	timer := time.NewTimer(next)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
			next = poll()
			timer.Reset(next)
		}
	}
}

func boundedPollInterval(seconds int, fallback time.Duration) time.Duration {
	if seconds <= 0 {
		return fallback
	}
	if seconds < 5 {
		seconds = 5
	}
	if seconds > 3600 {
		seconds = 3600
	}
	return time.Duration(seconds) * time.Second
}

func applyRemoteAgentConfig(objs bpf.Objects, flowFilter *flowFilter, fdFilterEnabled bool, cgroupFilterEnabled bool, cfg agentRemoteConfig) error {
	maxPayload, err := validateKernelMaxPayloadSize(cfg.MaxPayloadSize)
	if err != nil {
		return err
	}
	targetPorts := portSetFromInts(cfg.TargetPorts)
	ignorePorts := portSetFromInts(cfg.IgnorePorts)
	targetPortsEnabled := fdFilterEnabled && len(targetPorts) > 0
	if err := configureKernelCapture(objs.CaptureConfig, maxPayload, cfg.CaptureReadSyscalls, cfg.CaptureWriteSyscalls, cfg.AllowNonSocketFDs, targetPortsEnabled, cgroupFilterEnabled); err != nil {
		return err
	}
	if fdFilterEnabled {
		if err := configureKernelPortFilters(objs.TargetPorts, objs.IgnoredPorts, targetPorts, ignorePorts); err != nil {
			return err
		}
		if flowFilter != nil {
			flowFilter.update(targetPorts, ignorePorts, cfg.CaptureInbound, cfg.CaptureOutbound)
		}
	}
	return nil
}
