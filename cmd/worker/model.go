package main

import (
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	defaultTopic          = "raw-network-traffic"
	defaultBootstrap      = "localhost:9092"
	defaultGroupID        = "raven-worker-group"
	defaultOffsetReset    = "latest"
	defaultSessionTTL     = 60 * time.Second
	defaultStatsInterval  = 10 * time.Second
	defaultMaxBodyBytes   = 1024 * 1024
	defaultMaxStreamBytes = 8 * 1024 * 1024

	requestStartProbeWindow  = 16
	responseStartProbeWindow = 16

	eventTypeData  = 0
	eventTypeClose = 1

	directionRead  = 0
	directionWrite = 1
)

type config struct {
	bootstrapServers string
	topic            string
	groupID          string
	offsetReset      string
	sessionTTL       time.Duration
	statsInterval    time.Duration
	maxBodyBytes     int64
	maxStreamBytes   int
	prettyOutput     bool
	debugPayload     bool
	output           io.Writer
}

type workerStats struct {
	received             uint64
	decoded              uint64
	droppedMalformed     uint64
	droppedNoise         uint64
	outOfOrder           uint64
	routedReq            uint64
	routedResp           uint64
	routedUnknown        uint64
	requestParsed        uint64
	responseParsed       uint64
	requestParsePending  uint64
	responseParsePending uint64
	droppedNoReqStart    uint64
	droppedNoRespInit    uint64
	droppedReqOverflow   uint64
	droppedRespOverflow  uint64
	parsed               uint64
	closedSessions       uint64
	kafkaErrors          uint64
	expiredSessions      uint64
}

type payloadKind uint8

const (
	payloadUnknown payloadKind = iota
	payloadRequest
	payloadResponse
)

func (k payloadKind) String() string {
	switch k {
	case payloadRequest:
		return "request"
	case payloadResponse:
		return "response"
	default:
		return "unknown"
	}
}

type ApiEvent struct {
	Timestamp  uint64 `json:"timestamp"`
	PID        uint32 `json:"pid"`
	TID        uint32 `json:"tid"`
	FD         uint32 `json:"fd"`
	Generation uint32 `json:"generation"`
	Seq        uint32 `json:"seq"`
	ChunkIndex uint16 `json:"chunk_index"`
	ChunkCount uint16 `json:"chunk_count"`
	Direction  uint8  `json:"direction"`
	EventType  uint8  `json:"event_type"`
	Flags      uint8  `json:"flags"`
	Size       uint32 `json:"size"`
	Payload    []byte `json:"payload"`
}

type OIDField struct {
	OID string `json:"$oid"`
}

type DateField struct {
	Date string `json:"$date"`
}

type HttpConversation struct {
	ID         OIDField    `json:"_id"`
	CreatedAt  DateField   `json:"created_at"`
	Method     string      `json:"method"`
	URL        string      `json:"url"`
	Host       string      `json:"host"`
	Path       string      `json:"path"`
	ReqHeaders http.Header `json:"req_headers"`
	ReqBody    string      `json:"req_body"`
	RespStatus string      `json:"resp_status"`
	RespBody   string      `json:"resp_body"`
}

type parsedRequest struct {
	req        *http.Request
	body       string
	capturedAt time.Time
}

type StreamState struct {
	ReqData     []byte
	RespData    []byte
	PendingReqs []parsedRequest
	LastSeq     uint32
	mu          sync.Mutex
	LastActive  time.Time
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*StreamState
	ttl      time.Duration
}
