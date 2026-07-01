package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var h2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

type h2Stream struct {
	requestHeaders   http.Header
	requestBody      []byte
	responseHeaders  http.Header
	responseBody     []byte
	method           string
	path             string
	statusCode       int
	status           string
	requestComplete  bool
	responseComplete bool
}

func drainH2(cfg config, stats *processingStats, state *StreamState) int {
	if len(state.ReqData) >= len(h2Preface) && bytes.Equal(state.ReqData[:len(h2Preface)], h2Preface) {
		state.ReqData = state.ReqData[len(h2Preface):]
	}
	if len(state.RespData) >= len(h2Preface) && bytes.Equal(state.RespData[:len(h2Preface)], h2Preface) {
		state.RespData = state.RespData[len(h2Preface):]
	}

	streams := make(map[uint32]*h2Stream)
	parseHTTP2Frames(cfg, state.RespData, streams, false)
	parseHTTP2Frames(cfg, state.ReqData, streams, true)

	if state.H2Emitted == nil {
		state.H2Emitted = make(map[uint32]bool)
	}

	parsedCount := 0
	for streamID, stream := range streams {
		if !stream.requestComplete || !stream.responseComplete {
			continue
		}
		if state.H2Emitted[streamID] {
			continue
		}
		if err := emitH2Conversation(cfg, state, stream); err != nil {
			atomic.AddUint64(&stats.emitErrors, 1)
			log.Printf("h2 emit error stream=%d: %v", streamID, err)
		}
		state.H2Emitted[streamID] = true
		parsedCount++
	}
	return parsedCount
}

func parseHTTP2Frames(cfg config, buffer []byte, streams map[uint32]*h2Stream, isRequest bool) {
	framer := http2.NewFramer(nil, bytes.NewReader(buffer))
	framer.SetMaxReadFrameSize(1 << 20) // 1MB max frame size

	decoder := hpack.NewDecoder(4096, nil)

	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			if err != io.EOF && cfg.debugPayload {
				log.Printf("h2 frame read error isRequest=%t: %v", isRequest, err)
			}
			break
		}

		streamID := frame.Header().StreamID
		if streamID == 0 {
			// Connection-level frames (SETTINGS, WINDOW_UPDATE, PING, GOAWAY).
			continue
		}

		stream, exists := streams[streamID]
		if !exists {
			stream = &h2Stream{
				requestHeaders:  make(http.Header),
				responseHeaders: make(http.Header),
			}
			streams[streamID] = stream
		}

		switch f := frame.(type) {
		case *http2.HeadersFrame:
			headers, err := decoder.DecodeFull(f.HeaderBlockFragment())
			if err != nil {
				log.Printf("h2 hpack decode error stream=%d: %v", streamID, err)
				continue
			}

			if isRequest {
				for _, hf := range headers {
					stream.requestHeaders.Add(hf.Name, hf.Value)
					switch hf.Name {
					case ":method":
						stream.method = hf.Value
					case ":path":
						stream.path = hf.Value
					}
				}
				if f.StreamEnded() {
					stream.requestComplete = true
				}
			} else {
				for _, hf := range headers {
					stream.responseHeaders.Add(hf.Name, hf.Value)
					if hf.Name == ":status" {
						stream.status = hf.Value
						fmt.Sscanf(hf.Value, "%d", &stream.statusCode)
					}
				}
				if f.StreamEnded() {
					stream.responseComplete = true
				}
			}

		case *http2.DataFrame:
			data := f.Data()
			if isRequest {
				stream.requestBody = append(stream.requestBody, data...)
				if f.StreamEnded() {
					stream.requestComplete = true
				}
			} else {
				stream.responseBody = append(stream.responseBody, data...)
				if f.StreamEnded() {
					stream.responseComplete = true
				}
			}

		case *http2.RSTStreamFrame:
			if cfg.debugPayload {
				log.Printf("h2 stream reset stream=%d isRequest=%t errCode=%v", streamID, isRequest, f.ErrCode)
			}
		}
	}
}

func emitH2Conversation(cfg config, state *StreamState, stream *h2Stream) error {
	host := stream.requestHeaders.Get(":authority")
	if host == "" {
		host = stream.requestHeaders.Get("Host")
	}
	scheme := stream.requestHeaders.Get(":scheme")
	if scheme == "" {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s%s", scheme, host, stream.path)

	reqBody := prettyMaybeJSON(bodyBytesToString(stream.requestBody, cfg.maxBodyBytes))
	respBody := prettyMaybeJSON(bodyBytesToString(stream.responseBody, cfg.maxBodyBytes))

	statusCode := stream.statusCode
	normalized := NormalizedConversation{
		ID:            OIDField{OID: newOID()},
		SchemaVersion: "http.conversation.v1",
		AgentID:       cfg.agentID,
		CaptureSource: firstNonEmpty(state.CaptureSource, "ebpf"),
		CaptureMode:   state.CaptureMode,
		CapturedAt:    DateField{Date: time.Now().UTC().Format(time.RFC3339Nano)},
		Connection:    state.Connection,
		Process:       state.Process,
		Container:     state.Container,
		Loss:          state.Loss,
		HTTP: HTTPExchange{
			Request: NormalizedHTTPRequest{
				Method:  stream.method,
				URL:     url,
				Host:    host,
				Path:    stream.path,
				Headers: stream.requestHeaders,
				Body:    reqBody,
			},
			Response: NormalizedHTTPResponse{
				Status:     stream.status,
				StatusCode: &statusCode,
				Headers:    stream.responseHeaders,
				Body:       respBody,
			},
		},
	}

	return emitNormalized(cfg, normalized)
}
