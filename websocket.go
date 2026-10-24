// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2015 LabStack LLC and Echo contributors

package echo

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// TextMessage denotes a text data message. The text message payload is
	// interpreted as UTF-8 encoded text data.
	TextMessage = 1

	// BinaryMessage denotes a binary data message.
	BinaryMessage = 2

	// CloseMessage denotes a close control message.
	CloseMessage = 8

	// PingMessage denotes a ping control message.
	PingMessage = 9

	// PongMessage denotes a pong control message.
	PongMessage = 10
)

// Close codes defined in RFC 6455, section 11.7.
const (
	// CloseNormalClosure is the normal closure; the connection successfully completed whatever
	// purpose for which it was created.
	CloseNormalClosure = 1000
	// CloseGoingAway means an endpoint is going away, such as a server shutting down or a browser
	// having navigated away from a page.
	CloseGoingAway = 1001
	// CloseProtocolError indicates an endpoint is terminating the connection due to a protocol error.
	CloseProtocolError = 1002
	// CloseUnsupportedData indicates an endpoint received data of a type it cannot accept.
	CloseUnsupportedData = 1003
	// CloseNoStatusReceived is a reserved value that indicates no status code was present.
	// It MUST NOT be sent over the wire.
	CloseNoStatusReceived = 1005
	// CloseAbnormalClosure is a reserved value used when the connection was closed without sending or
	// receiving a Close control frame (for example on a TCP half-close). It MUST NOT be sent over the wire.
	CloseAbnormalClosure = 1006
	// ClosePolicyViolation indicates an endpoint received a message that violates its policy.
	ClosePolicyViolation = 1008
	// CloseMessageTooBig indicates an endpoint received a message that is too big for it to process.
	CloseMessageTooBig = 1009
	// CloseMandatoryExtension indicates an endpoint expected the server to negotiate one or more
	// extensions, but the server did not include them in the response.
	CloseMandatoryExtension = 1010
	// CloseInternalServerErr indicates an server is terminating the connection because it encountered
	// an unexpected condition that prevented it from fulfilling the request.
	CloseInternalServerErr = 1011
	// CloseServiceRestart indicates the server is terminating the connection because it is restarting.
	CloseServiceRestart = 1012
	// CloseTryAgainLater indicates the server is terminating the connection due to a temporary condition.
	CloseTryAgainLater = 1013
)

// websocketGUID is the magic GUID from RFC 6455 section 4.2.2 used to compute Sec-WebSocket-Accept.
const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

var (
	errWebSocketUpgradeMethod     = errors.New("websocket: handshake failed: upgrade request method must be GET")
	errWebSocketUpgradeConnection = errors.New("websocket: handshake failed: Connection header must contain Upgrade")
	errWebSocketUpgradeUpgrade    = errors.New("websocket: handshake failed: Upgrade header must contain websocket")
	errWebSocketUpgradeVersion    = errors.New("websocket: handshake failed: unsupported Sec-WebSocket-Version")
	errWebSocketUpgradeKey        = errors.New("websocket: handshake failed: Sec-WebSocket-Key must be 16 bytes base64 encoded nonce")
	errWebSocketUpgradeOrigin     = errors.New("websocket: handshake failed: origin not allowed")
	errWebSocketHijack            = errors.New("websocket: handshake failed: response writer does not support hijacking")
	errBadMessageType             = errors.New("websocket: message type must be TextMessage or BinaryMessage")
	errClientFrameNotMasked       = errors.New("websocket: client frames must be masked")
)

// Upgrader upgrades an HTTP connection to the WebSocket protocol (RFC 6455).
//
// The zero value is usable: origins are validated against the request Host by default and no
// subprotocols are negotiated.
type Upgrader struct {
	// HandshakeTimeout is the maximum duration the 101 Switching Protocols response may take to
	// be written. Zero means no timeout.
	HandshakeTimeout time.Duration

	// Subprotocols lists the websocket subprotocols (Sec-WebSocket-Protocol) that the server is
	// willing to negotiate. The first protocol requested by the client that appears in this list
	// is returned in the upgrade response.
	Subprotocols []string

	// CheckOrigin returns true if the request Origin header is acceptable. If nil, a safe default
	// is used: requests without an Origin header are allowed and requests with one are allowed only
	// when the Origin host is equal to the request Host.
	CheckOrigin func(r *http.Request) bool
}

// Upgrade upgrades the Echo request/response to a WebSocket connection.
//
// On a handshake failure Upgrade writes the appropriate HTTP error response itself (so the
// connection stays managed by net/http and can be reused with keep-alive) and returns the cause.
// On success the underlying TCP connection is hijacked and returned wrapped in a WSConn whose
// request context is canceled only when the connection is closed by either endpoint or by server
// shutdown. Callers must close the returned connection; the canonical pattern is
// `defer ws.Close()` right after a successful Upgrade.
func (u *Upgrader) Upgrade(c *Context) (*WSConn, error) {
	r := c.Request()
	w := c.Response()

	if r.Method != http.MethodGet {
		return nil, u.reject(w, http.StatusBadRequest, errWebSocketUpgradeMethod)
	}
	if !headerContainsToken(r.Header, HeaderConnection, "upgrade") {
		return nil, u.reject(w, http.StatusBadRequest, errWebSocketUpgradeConnection)
	}
	if !headerContainsToken(r.Header, HeaderUpgrade, "websocket") {
		return nil, u.reject(w, http.StatusBadRequest, errWebSocketUpgradeUpgrade)
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		// RFC 6455 4.4: a server that does not support the requested version MUST include
		// Sec-WebSocket-Version with the highest version it does support.
		w.Header().Set("Sec-WebSocket-Version", "13")
		return nil, u.reject(w, http.StatusUpgradeRequired, errWebSocketUpgradeVersion)
	}

	challengeKey := r.Header.Get("Sec-WebSocket-Key")
	keyBytes, err := base64.StdEncoding.DecodeString(challengeKey)
	if err != nil || len(keyBytes) != 16 {
		return nil, u.reject(w, http.StatusBadRequest, errWebSocketUpgradeKey)
	}

	checkOrigin := u.CheckOrigin
	if checkOrigin == nil {
		checkOrigin = checkSameOrigin
	}
	if !checkOrigin(r) {
		return nil, u.reject(w, http.StatusForbidden, errWebSocketUpgradeOrigin)
	}

	negotiatedProtocol := u.selectSubprotocol(r)

	// Hijack only after all handshake validation has succeeded. A failed handshake does not take
	// over the connection, so net/http keeps managing it and can keep it alive for further requests.
	rawConn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		// Nothing has been written yet, so leave error response production to the caller/error handler.
		return nil, fmt.Errorf("%w: %v", errWebSocketHijack, err)
	}

	// The websocket connection outlives the net/http request handler goroutine; derive a context
	// that WE cancel when the socket ends (close frame, read EOF/error or server shutdown) instead
	// of the implicit cancellation net/http performs when ServeHTTP returns.
	wsCtx, cancel := context.WithCancel(r.Context())
	conn := &WSConn{
		raw:       rawConn,
		brw:       brw,
		ctx:       wsCtx,
		cancel:    cancel,
		tracker:   hijackTrackerFromContext(r.Context()),
		closeCode: CloseNoStatusReceived,
	}
	if conn.tracker != nil {
		// Registered before the 101 is written so a shutdown racing the handshake still releases us.
		conn.tracker.add(rawConn, conn.closeForShutdown)
	}

	// net/http deadlines (e.g. http.Server.ReadTimeout) are set on the raw connection and stay in
	// effect after a hijack. Clear them so an idle websocket session is not silently torn down at the
	// HTTP read timeout; callers can still manage deadlines with SetReadDeadline/SetWriteDeadline.
	_ = rawConn.SetDeadline(time.Time{})
	if u.HandshakeTimeout > 0 {
		_ = rawConn.SetDeadline(time.Now().Add(u.HandshakeTimeout))
	}

	accept := computeAcceptKey(challengeKey)
	conn.writeMu.Lock()
	_, writeErr := fmt.Fprintf(brw,
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n",
		accept,
	)
	if writeErr == nil && negotiatedProtocol != "" {
		_, writeErr = fmt.Fprintf(brw, "Sec-WebSocket-Protocol: %s\r\n", negotiatedProtocol)
	}
	if writeErr == nil {
		_, writeErr = io.WriteString(brw, "\r\n")
	}
	if writeErr == nil {
		writeErr = brw.Flush()
	}
	conn.writeMu.Unlock()

	if u.HandshakeTimeout > 0 {
		_ = rawConn.SetDeadline(time.Time{})
	}

	if writeErr != nil {
		// The client may already be gone; there is no HTTP channel left to report through.
		// Release the hijacked connection and our derived request context.
		conn.shutdown()
		return nil, writeErr
	}

	// The socket now speaks websocket frames. Mark the Echo response committed so that an error
	// returned after the upgrade (or by a deferred middleware) is not serialized as HTTP onto the
	// hijacked connection by the error handler.
	if er, unwrapErr := UnwrapResponse(w); unwrapErr == nil {
		er.Committed = true
	}
	c.SetRequest(r.WithContext(wsCtx))

	return conn, nil
}

// reject writes the HTTP error response for a failed upgrade and returns the cause. The response is
// a regular HTTP response (the connection is never hijacked), so it is released back to net/http
// together with the request context when the handler returns.
func (u *Upgrader) reject(w http.ResponseWriter, status int, cause error) error {
	h := w.Header()
	h.Set(HeaderContentType, MIMETextPlainCharsetUTF8)
	h.Set(HeaderXContentTypeOptions, "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(stringToBytes(http.StatusText(status)))
	return cause
}

func (u *Upgrader) selectSubprotocol(r *http.Request) string {
	if len(u.Subprotocols) == 0 {
		return ""
	}
	for _, requested := range splitHeaderList(r.Header.Get("Sec-WebSocket-Protocol")) {
		for _, supported := range u.Subprotocols {
			if strings.EqualFold(requested, supported) {
				return supported
			}
		}
	}
	return ""
}

func checkSameOrigin(r *http.Request) bool {
	origin := r.Header.Get(HeaderOrigin)
	if origin == "" {
		// Non-browser clients do not send Origin.
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func computeAcceptKey(challengeKey string) string {
	h := sha1.New()
	h.Write([]byte(challengeKey))
	h.Write([]byte(websocketGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func headerContainsToken(h http.Header, name, token string) bool {
	for _, line := range h[http.CanonicalHeaderKey(name)] {
		for _, part := range strings.Split(line, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func splitHeaderList(value string) []string {
	parts := strings.Split(value, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}

// hijackTrackerFromContext extracts the per-server hijacked connection tracker injected through
// http.Server.BaseContext in StartConfig. It returns nil when Echo is served without StartConfig
// (for example directly via httptest.NewServer), in which case upgrades simply are not tracked.
func hijackTrackerFromContext(ctx context.Context) *hijackedConnTracker {
	if ctx == nil {
		return nil
	}
	tracker, _ := ctx.Value(serverContextKey{}).(*hijackedConnTracker)
	return tracker
}

// CloseError represents a close message received from the peer.
type CloseError struct {
	// Code is the status code carried by the close frame.
	Code int
	// Text is the optional close reason.
	Text string
}

// Error implements the error interface.
func (e *CloseError) Error() string {
	return fmt.Sprintf("websocket: close %d: %s", e.Code, e.Text)
}

// WSConn wraps the hijacked network connection of an upgraded WebSocket session.
//
// Concurrency: at most one goroutine may call ReadMessage at a time, while WriteMessage,
// WriteControl, Close and CloseWithCode may be called concurrently with ReadMessage and with
// each other. The connection (and its request context) is released exactly once, no matter which
// side initiates the close or how many times Close is called.
type WSConn struct {
	raw net.Conn
	// brw.Reader may already hold pipelined bytes after the hijack; all frame reads must go through it.
	brw    *bufio.ReadWriter
	ctx    context.Context
	cancel context.CancelFunc

	tracker *hijackedConnTracker

	readMu  sync.Mutex
	writeMu sync.Mutex

	closeMu   sync.Mutex
	closeSent bool
	// closeCode records the close code that was actually sent (or CloseAbnormalClosure when the
	// peer vanished without a close frame). It is written at most once, so a deferred Close() can
	// never overwrite a close code the application or peer chose.
	closeCode int

	shutdownOnce sync.Once
}

// ReadMessage reads the next complete data message. Control frames are handled automatically:
// Ping is answered with a matching Pong and a received Close frame is echoed back to the peer.
//
// It returns a *CloseError when the peer closed the handshake, io.EOF when the peer half-closed
// the TCP connection (FIN) without a close frame, or another net error. In every terminal case the
// connection is shut down and the request context is canceled.
func (conn *WSConn) ReadMessage() (messageType int, payload []byte, err error) {
	conn.readMu.Lock()
	defer conn.readMu.Unlock()

	var message []byte
	for {
		frame, frameErr := readFrame(conn.brw.Reader)
		if frameErr != nil {
			if errors.Is(frameErr, errClientFrameNotMasked) {
				return 0, nil, conn.protocolError(CloseProtocolError, "client frame is not masked")
			}
			// io.EOF (clean FIN, i.e. client half-close), timeout or reset: nothing more can be
			// read. Release the connection and context instead of leaving the session dangling.
			conn.closeMu.Lock()
			if !conn.closeSent {
				conn.closeCode = CloseAbnormalClosure
			}
			conn.closeMu.Unlock()
			conn.shutdown()
			return 0, nil, frameErr
		}

		if frame.rsv != 0 {
			return 0, nil, conn.protocolError(CloseProtocolError, "RSV bits must be zero")
		}

		if frame.opcode >= 8 { // control frame
			if !frame.fin || len(frame.payload) > 125 {
				return 0, nil, conn.protocolError(CloseProtocolError, "malformed control frame")
			}
			if err := conn.handleControl(frame.opcode, frame.payload); err != nil {
				return 0, nil, err
			}
			continue
		}

		switch frame.opcode {
		case 0: // continuation
			if messageType == 0 {
				return 0, nil, conn.protocolError(CloseProtocolError, "unexpected continuation frame")
			}
		case TextMessage, BinaryMessage:
			if messageType != 0 {
				return 0, nil, conn.protocolError(CloseProtocolError, "new data frame before previous message finished")
			}
			messageType = int(frame.opcode)
		default:
			return 0, nil, conn.protocolError(CloseProtocolError, fmt.Sprintf("reserved opcode %d", frame.opcode))
		}
		message = append(message, frame.payload...)

		if frame.fin {
			return messageType, message, nil
		}
	}
}

func (conn *WSConn) handleControl(opcode byte, payload []byte) error {
	switch opcode {
	case CloseMessage:
		switch {
		case len(payload) == 0:
			// RFC 6455 5.5.1: a close without a status code must be echoed with an empty payload;
			// status 1005 is a local marker and MUST NOT be put on the wire.
			if conn.markCloseSent(CloseNoStatusReceived) {
				_ = conn.writeFrame(CloseMessage, nil)
			}
			conn.shutdown()
			return &CloseError{Code: CloseNoStatusReceived}
		case len(payload) == 1:
			return conn.protocolError(CloseProtocolError, "close frame payload must be at least 2 bytes")
		default:
			code := int(binary.BigEndian.Uint16(payload[:2]))
			if !isValidCloseCode(code) {
				return conn.protocolError(CloseProtocolError, fmt.Sprintf("invalid close code %d", code))
			}
			reason := string(payload[2:])
			// RFC 6455 5.5.1: echo the received close frame back, then drop the connection. The first
			// close code wins; an application Close() afterwards must not overwrite it.
			_ = conn.sendClose(code, reason)
			conn.shutdown()
			return &CloseError{Code: code, Text: reason}
		}
	case PingMessage:
		// Respond with an identical Pong payload.
		return conn.writeFrame(PongMessage, payload)
	case PongMessage:
		return nil
	default:
		return conn.protocolError(CloseProtocolError, fmt.Sprintf("reserved control opcode %d", opcode))
	}
}

func (conn *WSConn) protocolError(code int, reason string) error {
	_ = conn.sendClose(code, reason)
	conn.shutdown()
	return &CloseError{Code: code, Text: reason}
}

// WriteMessage writes a complete (single, FIN) text or binary data message. Server messages are
// sent unmasked as required by RFC 6455.
func (conn *WSConn) WriteMessage(messageType int, data []byte) error {
	if messageType != TextMessage && messageType != BinaryMessage {
		return errBadMessageType
	}
	return conn.writeFrame(byte(messageType), data)
}

// WriteControl writes a control message. For CloseMessage, data must be the output of
// FormatCloseMessage; the embedded close code is recorded at most once, so a close frame already
// sent by the application or echoed from the peer is not overwritten.
//
// A zero deadline writes without a write deadline.
func (conn *WSConn) WriteControl(messageType int, data []byte, deadline time.Time) error {
	if !deadline.IsZero() {
		_ = conn.raw.SetWriteDeadline(deadline)
		defer conn.raw.SetWriteDeadline(time.Time{}) //nolint:errcheck // best effort restore
	}

	switch messageType {
	case CloseMessage:
		code := CloseNoStatusReceived
		reason := ""
		if len(data) >= 2 {
			code = int(binary.BigEndian.Uint16(data[:2]))
			reason = string(data[2:])
		}
		return conn.sendClose(code, reason)
	case PingMessage, PongMessage:
		return conn.writeFrame(byte(messageType), data)
	default:
		return errBadMessageType
	}
}

// Close performs the WebSocket closing handshake with CloseNormalClosure and then closes the
// underlying connection. It is safe to call multiple times and from multiple goroutines: if a
// close frame was already sent (by the application, echoed from the peer or triggered by server
// shutdown) no second close frame is written and the first close code is kept.
func (conn *WSConn) Close() error {
	conn.closeMu.Lock()
	alreadySent := conn.closeSent
	conn.closeMu.Unlock()

	if !alreadySent {
		if err := conn.sendClose(CloseNormalClosure, ""); err != nil && !errors.Is(err, net.ErrClosed) {
			conn.shutdown()
			return err
		}
	}
	conn.shutdown()
	return nil
}

// CloseWithCode performs the WebSocket closing handshake with the given code and reason and then
// closes the underlying connection. The same once-only close semantics as Close apply.
func (conn *WSConn) CloseWithCode(code int, reason string) error {
	conn.closeMu.Lock()
	alreadySent := conn.closeSent
	conn.closeMu.Unlock()

	if !alreadySent {
		if err := conn.sendClose(code, reason); err != nil && !errors.Is(err, net.ErrClosed) {
			conn.shutdown()
			return err
		}
	}
	conn.shutdown()
	return nil
}

// closeForShutdown is registered with the server connection tracker: a graceful server shutdown
// sends a GoingAway close frame (unless the application already sent one) and releases the socket,
// which in turn unblocks any ReadMessage and cancels the request context.
func (conn *WSConn) closeForShutdown() {
	conn.closeMu.Lock()
	alreadySent := conn.closeSent
	conn.closeMu.Unlock()
	if !alreadySent {
		_ = conn.sendClose(CloseGoingAway, "")
	}
	conn.shutdown()
}

// sendClose writes a close frame unless one has already been written. The first close code wins.
func (conn *WSConn) sendClose(code int, reason string) error {
	if code < 0 || code > 0xffff {
		code = ClosePolicyViolation
	}
	if len(reason) > 123 { // 2 byte code + max 125 byte control payload
		reason = reason[:123]
	}
	if !conn.markCloseSent(code) {
		return nil
	}

	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload, uint16(code))
	copy(payload[2:], reason)
	return conn.writeFrame(CloseMessage, payload)
}

// markCloseSent records the close code being sent. It returns false when a close frame was
// already recorded, in which case callers must not send another one.
func (conn *WSConn) markCloseSent(code int) bool {
	conn.closeMu.Lock()
	defer conn.closeMu.Unlock()
	if conn.closeSent {
		return false
	}
	conn.closeSent = true
	conn.closeCode = code
	return true
}

// CloseCode returns the close code that was sent to the peer, CloseNoStatusReceived while the
// session is still open, or CloseAbnormalClosure when the peer vanished without a close handshake.
func (conn *WSConn) CloseCode() int {
	conn.closeMu.Lock()
	defer conn.closeMu.Unlock()
	return conn.closeCode
}

// shutdown releases the raw connection, deregisters it from the server tracker and cancels the
// request context. It is idempotent.
func (conn *WSConn) shutdown() {
	conn.shutdownOnce.Do(func() {
		if conn.tracker != nil {
			conn.tracker.remove(conn.raw)
		}
		_ = conn.raw.Close()
		if conn.cancel != nil {
			conn.cancel()
		}
	})
}

// Context returns the request-scoped context bound to the websocket session. It is canceled when
// the connection closes (either endpoint, read failure or server shutdown).
func (conn *WSConn) Context() context.Context {
	return conn.ctx
}

// SetReadDeadline sets the deadline for future ReadMessage calls. A zero time clears the deadline.
func (conn *WSConn) SetReadDeadline(t time.Time) error {
	return conn.raw.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future WriteMessage and WriteControl calls.
func (conn *WSConn) SetWriteDeadline(t time.Time) error {
	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()
	return conn.raw.SetWriteDeadline(t)
}

// RemoteAddr returns the remote network address of the underlying connection.
func (conn *WSConn) RemoteAddr() net.Addr {
	return conn.raw.RemoteAddr()
}

// LocalAddr returns the local network address of the underlying connection.
func (conn *WSConn) LocalAddr() net.Addr {
	return conn.raw.LocalAddr()
}

// NetConn returns the underlying hijacked connection. It is exposed for advanced use (TCP-level
// deadlines, keepalive); callers must not close it directly, use Close instead.
func (conn *WSConn) NetConn() net.Conn {
	return conn.raw
}

func (conn *WSConn) writeFrame(opcode byte, payload []byte) error {
	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()

	var header [10]byte
	header[0] = 0x80 | (opcode & 0x0f) // FIN set; server does not fragment or use extensions

	n := len(payload)
	headerLen := 2
	switch {
	case n <= 125:
		header[1] = byte(n)
	case n <= 65535:
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:4], uint16(n))
		headerLen = 4
	default:
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:10], uint64(n))
		headerLen = 10
	}
	// Server frames are never masked (mask bit 0).
	if _, err := conn.brw.Write(header[:headerLen]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := conn.brw.Write(payload); err != nil {
			return err
		}
	}
	return conn.brw.Flush()
}

// FormatCloseMessage returns the payload of a Close control frame carrying code and text, ready
// for use with WriteControl.
func FormatCloseMessage(code int, text string) []byte {
	if len(text) > 123 {
		text = text[:123]
	}
	buf := make([]byte, 2+len(text))
	binary.BigEndian.PutUint16(buf, uint16(code))
	copy(buf[2:], text)
	return buf
}

func isValidCloseCode(code int) bool {
	switch code {
	case CloseNormalClosure,
		CloseGoingAway,
		CloseProtocolError,
		CloseUnsupportedData,
		ClosePolicyViolation,
		CloseMessageTooBig,
		CloseMandatoryExtension,
		CloseInternalServerErr,
		CloseServiceRestart,
		CloseTryAgainLater:
		return true
	}
	return code >= 3000 && code <= 4999
}

type wsFrame struct {
	fin     bool
	rsv     byte
	opcode  byte
	payload []byte
}

// readFrame parses one RFC 6455 frame and unmasks client frames in place.
func readFrame(r io.Reader) (wsFrame, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		// io.ReadFull returns io.EOF when not a single byte was read (TCP half-close) and
		// io.ErrUnexpectedEOF when the stream ended mid-frame.
		return wsFrame{}, err
	}

	b0, b1 := header[0], header[1]
	frame := wsFrame{
		fin:    b0&0x80 != 0,
		rsv:    b0 & 0x70,
		opcode: b0 & 0x0f,
	}

	masked := b1&0x80 != 0
	payloadLen := uint64(b1 & 0x7f)
	switch payloadLen {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return wsFrame{}, err
		}
		payloadLen = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return wsFrame{}, err
		}
		payloadLen = binary.BigEndian.Uint64(ext[:])
	}

	var maskingKey [4]byte
	if masked {
		if _, err := io.ReadFull(r, maskingKey[:]); err != nil {
			return wsFrame{}, err
		}
	}

	// RFC 6455 5.1: all frames sent from client to server MUST be masked.
	if !masked {
		return wsFrame{}, errClientFrameNotMasked
	}

	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return wsFrame{}, err
		}
		for i := range payload {
			payload[i] ^= maskingKey[i%4]
		}
	}
	frame.payload = payload
	return frame, nil
}
