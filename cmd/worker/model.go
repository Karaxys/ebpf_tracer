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
	defaultOutputSink     = outputSinkStdout
	defaultOutputTopic    = "karaxys.http.conversations"
	defaultHTTPTimeout    = 10 * time.Second
	defaultHTTPMaxRetries = 3
	defaultHTTPRetryDelay = 500 * time.Millisecond

	requestStartProbeWindow  = 16
	responseStartProbeWindow = 16

	eventTypeData  = 0
	eventTypeClose = 1

	directionRead  = 0
	directionWrite = 1

	outputSinkStdout = "stdout"
	outputSinkHTTP   = "http"
	outputSinkKafka  = "kafka"
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
	outputContract   string
	output           io.Writer
	outputSink       string
	backendURL       string
	agentToken       string
	agentID          string
	httpTimeout      time.Duration
	httpMaxRetries   int
	httpRetryDelay   time.Duration
	deadLetterFile   string
	outputTopic      string
	outputBootstrap  string
	sink             conversationSink
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
	SchemaVersion string             `json:"schema_version,omitempty"`
	CaptureSource string             `json:"capture_source,omitempty"`
	CaptureMode   string             `json:"capture_mode,omitempty"`
	Timestamp     uint64             `json:"timestamp"`
	PID           uint32             `json:"pid"`
	TID           uint32             `json:"tid"`
	FD            uint32             `json:"fd"`
	Generation    uint32             `json:"generation"`
	Seq           uint32             `json:"seq"`
	ChunkIndex    uint16             `json:"chunk_index"`
	ChunkCount    uint16             `json:"chunk_count"`
	Direction     uint8              `json:"direction"`
	EventType     uint8              `json:"event_type"`
	Flags         uint8              `json:"flags"`
	OriginalSize  uint32             `json:"original_size,omitempty"`
	Size          uint32             `json:"size"`
	Payload       []byte             `json:"payload"`
	Connection    ConnectionMetadata `json:"connection,omitempty"`
	Process       ProcessMetadata    `json:"process,omitempty"`
	Container     ContainerMetadata  `json:"container,omitempty"`
	Loss          LossMetadata       `json:"loss,omitempty"`
}

type OIDField struct {
	OID string `json:"$oid"`
}

type DateField struct {
	Date string `json:"$date"`
}

type ConnectionMetadata struct {
	SrcIP    string `json:"src_ip,omitempty"`
	SrcPort  int    `json:"src_port,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	DstPort  int    `json:"dst_port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Family   string `json:"family,omitempty"`
	Role     string `json:"role,omitempty"`
}

type ProcessMetadata struct {
	PID  uint32 `json:"pid,omitempty"`
	Name string `json:"name,omitempty"`
	Exe  string `json:"exe,omitempty"`
}

type ContainerMetadata struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	Image     string `json:"image,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Pod       string `json:"pod,omitempty"`
	Node      string `json:"node,omitempty"`
	Runtime   string `json:"runtime,omitempty"`
	PodUID    string `json:"pod_uid,omitempty"`
}

type LossMetadata struct {
	Truncated       bool   `json:"truncated,omitempty"`
	OriginalSize    uint32 `json:"original_size,omitempty"`
	CapturedSize    uint32 `json:"captured_size,omitempty"`
	Reason          string `json:"reason,omitempty"`
	SequenceGap     bool   `json:"sequence_gap,omitempty"`
	ExpectedNextSeq uint32 `json:"expected_next_seq,omitempty"`
	ActualSeq       uint32 `json:"actual_seq,omitempty"`
}

type HttpMessage struct {
	Headers http.Header `json:"headers,omitempty"`
	Body    string      `json:"body,omitempty"`
	Status  string      `json:"status,omitempty"`
}

type NormalizedConversation struct {
	ID            OIDField           `json:"_id"`
	SchemaVersion string             `json:"schema_version"`
	AgentID       string             `json:"agent_id,omitempty"`
	CaptureSource string             `json:"capture_source"`
	CaptureMode   string             `json:"capture_mode,omitempty"`
	CapturedAt    DateField          `json:"captured_at"`
	Connection    ConnectionMetadata `json:"connection,omitempty"`
	Process       ProcessMetadata    `json:"process,omitempty"`
	Container     ContainerMetadata  `json:"container,omitempty"`
	Loss          LossMetadata       `json:"loss,omitempty"`
	HTTP          HTTPExchange       `json:"http"`
}

type HTTPExchange struct {
	Request  NormalizedHTTPRequest  `json:"request"`
	Response NormalizedHTTPResponse `json:"response"`
}

type NormalizedHTTPRequest struct {
	Method  string      `json:"method"`
	URL     string      `json:"url"`
	Host    string      `json:"host"`
	Path    string      `json:"path"`
	Headers http.Header `json:"headers,omitempty"`
	Body    string      `json:"body,omitempty"`
}

type NormalizedHTTPResponse struct {
	Status     string      `json:"status"`
	StatusCode *int        `json:"status_code,omitempty"`
	Headers    http.Header `json:"headers,omitempty"`
	Body       string      `json:"body,omitempty"`
}

type HttpConversation struct {
	ID            OIDField           `json:"_id"`
	SchemaVersion string             `json:"schema_version,omitempty"`
	CaptureSource string             `json:"capture_source,omitempty"`
	CaptureMode   string             `json:"capture_mode,omitempty"`
	CreatedAt     DateField          `json:"created_at"`
	Connection    ConnectionMetadata `json:"connection,omitempty"`
	Process       ProcessMetadata    `json:"process,omitempty"`
	Container     ContainerMetadata  `json:"container,omitempty"`
	Loss          LossMetadata       `json:"loss,omitempty"`
	Request       HttpMessage        `json:"request,omitempty"`
	Response      HttpMessage        `json:"response,omitempty"`
	Method        string             `json:"method"`
	URL           string             `json:"url"`
	Host          string             `json:"host"`
	Path          string             `json:"path"`
	ReqHeaders    http.Header        `json:"req_headers"`
	ReqBody       string             `json:"req_body"`
	RespStatus    string             `json:"resp_status"`
	RespBody      string             `json:"resp_body"`
}

type parsedRequest struct {
	req           *http.Request
	body          string
	capturedAt    time.Time
	captureSource string
	captureMode   string
	connection    ConnectionMetadata
	process       ProcessMetadata
	container     ContainerMetadata
	loss          LossMetadata
}

type StreamState struct {
	ReqData       []byte
	RespData      []byte
	PendingReqs   []parsedRequest
	LastSeq       uint32
	HasLastSeq    bool
	CaptureSource string
	CaptureMode   string
	Connection    ConnectionMetadata
	Process       ProcessMetadata
	Container     ContainerMetadata
	Loss          LossMetadata
	mu            sync.Mutex
	LastActive    time.Time
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*StreamState
	ttl      time.Duration
}
