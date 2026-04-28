package main

import (
	"flag"
	"log"
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
		output:           os.Stdout,
	}
}
