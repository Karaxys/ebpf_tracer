package main

import (
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
)

func main() {
	cfg := parseConfig()
	sink, err := newConversationSink(cfg)
	if err != nil {
		log.Fatalf("Failed to create output sink: %s", err)
	}
	if sink != nil {
		cfg.sink = sink
		defer sink.Close()
	}

	consumer, err := kafka.NewConsumer(&kafka.ConfigMap{
		"bootstrap.servers": cfg.bootstrapServers,
		"group.id":          cfg.groupID,
		"auto.offset.reset": cfg.offsetReset,
	})
	if err != nil {
		log.Fatalf("Failed to create consumer: %s", err)
	}
	defer consumer.Close()

	if err := consumer.SubscribeTopics([]string{cfg.topic}, nil); err != nil {
		log.Fatalf("Failed to subscribe: %s", err)
	}

	log.Printf("Worker started. topic=%s group=%s bootstrap=%s output_sink=%s", cfg.topic, cfg.groupID, cfg.bootstrapServers, cfg.outputSink)

	store := newSessionStore(cfg.sessionTTL)
	stats := &workerStats{}

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigchan)

	stopCh := make(chan struct{})
	go runSessionCleanup(store, cfg, stats, stopCh)
	go runStatsReporter(cfg, stats, stopCh)
	defer close(stopCh)

	running := true
	for running {
		select {
		case sig := <-sigchan:
			log.Printf("Caught signal %v: terminating\n", sig)
			running = false
		default:
			ev := consumer.Poll(100)
			if ev == nil {
				continue
			}

			switch e := ev.(type) {
			case *kafka.Message:
				atomic.AddUint64(&stats.received, 1)
				var rawEvent ApiEvent
				if err := json.Unmarshal(e.Value, &rawEvent); err != nil {
					atomic.AddUint64(&stats.droppedMalformed, 1)
					log.Printf("Skipping malformed event: %v", err)
					continue
				}
				atomic.AddUint64(&stats.decoded, 1)
				processEvent(store, cfg, stats, rawEvent)
			case kafka.Error:
				atomic.AddUint64(&stats.kafkaErrors, 1)
				log.Printf("Kafka Error: %v\n", e)
			}
		}
	}

	logStats("shutdown", stats)
}
