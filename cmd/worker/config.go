package main

import (
	"flag"
	"log"
	"net/url"
	"os"
)

func parseConfig() config {
	bootstrap := flag.String("kafka-bootstrap", defaultBootstrap, "Kafka bootstrap servers")
	topic := flag.String("topic", defaultTopic, "Kafka topic to consume")
	groupID := flag.String("group-id", defaultGroupID, "Kafka consumer group id")
	offsetReset := flag.String("offset-reset", defaultOffsetReset, "Kafka offset reset policy: latest or earliest")
	sessionTTL := flag.Duration("session-ttl", defaultSessionTTL, "Session expiration interval")
	statsInterval := flag.Duration("stats-interval", defaultStatsInterval, "Periodic stats log interval")
	maxBodyBytes := flag.Int64("max-body-bytes", defaultMaxBodyBytes, "Max request/response body bytes to retain")
	maxStreamBytes := flag.Int("max-stream-bytes", defaultMaxStreamBytes, "Max buffered bytes per request/response stream before reset")
	pretty := flag.Bool("pretty", true, "Pretty-print conversation output")
	debugPayload := flag.Bool("debug-payload", false, "Log short escaped payload previews while routing events")
	outputContract := flag.String("output-contract", "normalized", "Output contract: normalized, legacy, or both")
	outputSink := flag.String("output-sink", envString("KARAXYS_OUTPUT_SINK", defaultOutputSink), "Conversation output sink: stdout, http, or kafka")
	// Account-token mode (preferred for new deployments).
	ingestURL    := flag.String("ingest-url", os.Getenv("KARAXYS_INGEST_URL"), "Full URL of the POST /ingest endpoint (e.g. https://karaxys.example.com/ingest)")
	accountToken := flag.String("account-token", os.Getenv("KARAXYS_ACCOUNT_TOKEN"), "Karaxys account-level ingest token (no enrollment required)")
	// Legacy enrollment-based mode (kept for backward compat).
	backendURL := flag.String("backend-url", os.Getenv("KARAXYS_BACKEND_URL"), "Karaxys backend base URL for HTTP sink (legacy; use -ingest-url instead)")
	agentToken := flag.String("agent-token", os.Getenv("KARAXYS_AGENT_TOKEN"), "Karaxys per-agent token for HTTP sink (legacy; use -account-token instead)")
	agentID := flag.String("agent-id", os.Getenv("KARAXYS_AGENT_ID"), "Optional agent id included in emitted conversations")
	httpTimeout := flag.Duration("http-timeout", defaultHTTPTimeout, "HTTP sink request timeout")
	httpMaxRetries := flag.Int("http-max-retries", defaultHTTPMaxRetries, "HTTP sink max retry attempts after the first request")
	httpRetryDelay := flag.Duration("http-retry-delay", defaultHTTPRetryDelay, "HTTP sink initial retry delay")
	deadLetterFile := flag.String("dead-letter-file", os.Getenv("KARAXYS_DEAD_LETTER_FILE"), "Optional JSONL file for sink delivery failures")
	outputTopic := flag.String("output-topic", envString("KARAXYS_OUTPUT_TOPIC", defaultOutputTopic), "Kafka output topic for normalized conversations")
	outputBootstrap := flag.String("output-kafka-bootstrap", os.Getenv("KARAXYS_OUTPUT_KAFKA_BOOTSTRAP"), "Kafka bootstrap servers for conversation output sink")
	flag.Parse()

	if *offsetReset != "latest" && *offsetReset != "earliest" {
		log.Fatalf("Invalid -offset-reset value %q, expected latest or earliest", *offsetReset)
	}

	if *maxBodyBytes <= 0 {
		log.Fatalf("-max-body-bytes must be > 0")
	}

	if *maxStreamBytes <= 0 {
		log.Fatalf("-max-stream-bytes must be > 0")
	}

	if *outputContract != "normalized" && *outputContract != "legacy" && *outputContract != "both" {
		log.Fatalf("Invalid -output-contract value %q, expected normalized, legacy, or both", *outputContract)
	}

	switch *outputSink {
	case outputSinkStdout, outputSinkHTTP, outputSinkKafka:
	default:
		log.Fatalf("Invalid -output-sink value %q, expected stdout, http, or kafka", *outputSink)
	}

	if *httpTimeout <= 0 {
		log.Fatalf("-http-timeout must be > 0")
	}
	if *httpMaxRetries < 0 {
		log.Fatalf("-http-max-retries must be >= 0")
	}
	if *httpRetryDelay < 0 {
		log.Fatalf("-http-retry-delay must be >= 0")
	}

	if *outputSink == outputSinkHTTP {
		if *outputContract != "normalized" {
			log.Fatalf("-output-sink=http requires -output-contract=normalized")
		}

		// New mode: KARAXYS_INGEST_URL + KARAXYS_ACCOUNT_TOKEN (no enrollment).
		// Legacy mode: KARAXYS_BACKEND_URL + KARAXYS_AGENT_TOKEN (enrollment-based).
		// New mode takes priority; both modes require a URL and a token.
		usingNewMode := *ingestURL != "" || *accountToken != ""
		usingLegacyMode := *backendURL != "" || *agentToken != ""

		if !usingNewMode && !usingLegacyMode {
			log.Fatalf("-output-sink=http requires either:\n" +
				"  New:    -ingest-url / KARAXYS_INGEST_URL  +  -account-token / KARAXYS_ACCOUNT_TOKEN\n" +
				"  Legacy: -backend-url / KARAXYS_BACKEND_URL  +  -agent-token / KARAXYS_AGENT_TOKEN")
		}

		if usingNewMode {
			if *ingestURL == "" {
				log.Fatalf("-ingest-url or KARAXYS_INGEST_URL is required when -account-token is set")
			}
			if *accountToken == "" {
				log.Fatalf("-account-token or KARAXYS_ACCOUNT_TOKEN is required when -ingest-url is set")
			}
			parsed, err := url.ParseRequestURI(*ingestURL)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" {
				log.Fatalf("-ingest-url must be an absolute http(s) URL, got %q", *ingestURL)
			}
			if parsed.Scheme != "http" && parsed.Scheme != "https" {
				log.Fatalf("-ingest-url must use http or https, got scheme %q", parsed.Scheme)
			}
		} else {
			// Legacy mode validation.
			if *backendURL == "" {
				log.Fatalf("-backend-url or KARAXYS_BACKEND_URL is required for -output-sink=http")
			}
			parsed, err := url.ParseRequestURI(*backendURL)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" {
				log.Fatalf("-backend-url must be an absolute http(s) URL, got %q", *backendURL)
			}
			if parsed.Scheme != "http" && parsed.Scheme != "https" {
				log.Fatalf("-backend-url must use http or https, got scheme %q", parsed.Scheme)
			}
			if *agentToken == "" {
				log.Fatalf("-agent-token or KARAXYS_AGENT_TOKEN is required for -output-sink=http")
			}
		}
	}

	outputBootstrapValue := *outputBootstrap
	if outputBootstrapValue == "" {
		outputBootstrapValue = *bootstrap
	}
	if *outputSink == outputSinkKafka && *outputTopic == "" {
		log.Fatalf("-output-topic must be set for -output-sink=kafka")
	}

	return config{
		bootstrapServers: *bootstrap,
		topic:            *topic,
		groupID:          *groupID,
		offsetReset:      *offsetReset,
		sessionTTL:       *sessionTTL,
		statsInterval:    *statsInterval,
		maxBodyBytes:     *maxBodyBytes,
		maxStreamBytes:   *maxStreamBytes,
		prettyOutput:     *pretty,
		debugPayload:     *debugPayload,
		outputContract:   *outputContract,
		output:           os.Stdout,
		outputSink:       *outputSink,
		ingestURL:        *ingestURL,
		accountToken:     *accountToken,
		backendURL:       *backendURL,
		agentToken:       *agentToken,
		agentID:          *agentID,
		httpTimeout:      *httpTimeout,
		httpMaxRetries:   *httpMaxRetries,
		httpRetryDelay:   *httpRetryDelay,
		deadLetterFile:   *deadLetterFile,
		outputTopic:      *outputTopic,
		outputBootstrap:  outputBootstrapValue,
	}
}

func envString(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
