// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2015 LabStack LLC and Echo contributors

package echo

import (
	"bufio"
	"bytes"
	stdContext "context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wsTestClient is a minimal raw RFC 6455 client used in these tests. It talks to the server over a
// plain TCP socket so that handshake edge cases (invalid headers, missing key, half-close) and
// close codes can be observed exactly as they are put on the wire.
type wsTestClient struct {
	t   *testing.T
	raw net.Conn
	br  *bufio.Reader
}

func newWsTestClient(t *testing.T, addr string) *wsTestClient {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return &wsTestClient{t: t, raw: conn, br: bufio.NewReader(conn)}
}

func wsNonce() string {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	return base64.StdEncoding.EncodeToString(nonce)
}

// sendRequest writes one HTTP/1.1 request to /ws with exactly the given header lines (plus an
// empty trailing line). It gives the tests full control over malformed handshakes.
func (c *wsTestClient) sendRequest(method string, headers ...string) {
	c.t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "%s /ws HTTP/1.1\r\n", method)
	for _, h := range headers {
		b.WriteString(h)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	_, err := c.raw.Write([]byte(b.String()))
	require.NoError(c.t, err)
}

func (c *wsTestClient) sendPlain(path string) {
	c.t.Helper()
	_, err := fmt.Fprintf(c.raw, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", path, c.raw.RemoteAddr().String())
	require.NoError(c.t, err)
}

func (c *wsTestClient) readResponse(method string) *http.Response {
	c.t.Helper()
	resp, err := http.ReadResponse(c.br, &http.Request{Method: method})
	require.NoError(c.t, err)
	return resp
}

func (c *wsTestClient) writeFrame(fin bool, opcode byte, payload []byte) {
	c.t.Helper()
	var b bytes.Buffer
	b0 := opcode
	if fin {
		b0 |= 0x80
	}
	_ = b.WriteByte(b0)

	n := len(payload)
	switch {
	case n <= 125:
		_ = b.WriteByte(byte(n) | 0x80) // client frames are always masked
	case n <= 65535:
		_ = b.WriteByte(126 | 0x80)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		_, _ = b.Write(ext[:])
	default:
		_ = b.WriteByte(127 | 0x80)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		_, _ = b.Write(ext[:])
	}

	var mask [4]byte
	_, _ = rand.Read(mask[:])
	_, _ = b.Write(mask[:])
	masked := make([]byte, n)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	_, _ = b.Write(masked)

	_, err := c.raw.Write(b.Bytes())
	require.NoError(c.t, err)
}

func (c *wsTestClient) writeClose(code int, reason string) {
	payload := FormatCloseMessage(code, reason)
	c.writeFrame(true, CloseMessage, payload)
}

// readFrame reads one frame from the server. Server frames must not be masked.
func (c *wsTestClient) readFrame() (fin bool, opcode byte, payload []byte, err error) {
	var header [2]byte
	if _, err = io.ReadFull(c.br, header[:]); err != nil {
		return false, 0, nil, err
	}
	fin = header[0]&0x80 != 0
	opcode = header[0] & 0x0f
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(c.br, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(c.br, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(c.br, mask[:]); err != nil {
			return false, 0, nil, err
		}
	}
	payload = make([]byte, length)
	if length > 0 {
		if _, err = io.ReadFull(c.br, payload); err != nil {
			return false, 0, nil, err
		}
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return fin, opcode, payload, nil
}

func (c *wsTestClient) setReadDeadline(d time.Duration) {
	_ = c.raw.SetReadDeadline(time.Now().Add(d))
}

func (c *wsTestClient) clearReadDeadline() {
	_ = c.raw.SetReadDeadline(time.Time{})
}

func (c *wsTestClient) halfCloseWrite() {
	require.NoError(c.t, c.raw.(*net.TCPConn).CloseWrite())
}

func closeCodeFromFrame(t *testing.T, payload []byte) int {
	t.Helper()
	require.GreaterOrEqual(t, len(payload), 2, "close frame must carry a code")
	return int(binary.BigEndian.Uint16(payload[:2]))
}

func newWSTestServer(t *testing.T, upgrader *Upgrader, handler HandlerFunc) *httptest.Server {
	t.Helper()
	e := New()
	if upgrader == nil {
		upgrader = &Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	}
	wrapped := func(c *Context) error {
		return handler(c)
	}
	// Any so malformed POST handshakes also reach the upgrader.
	e.Any("/ws", wrapped)
	e.GET("/plain", func(c *Context) error {
		return c.String(http.StatusOK, "plain ok")
	})
	ts := httptest.NewServer(e)
	t.Cleanup(ts.Close)
	return ts
}

func newTestUpgrader() *Upgrader {
	return &Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
}

func TestUpgrader_HandshakeFailures(t *testing.T) {
	t.Parallel()

	upgraded := make(chan struct{}, 1)
	upgrader := newTestUpgrader()
	ts := newWSTestServer(t, upgrader, func(c *Context) error {
		var u Upgrader
		ws, err := u.Upgrade(c)
		if err != nil {
			return err
		}
		upgraded <- struct{}{}
		_ = ws.Close()
		return nil
	})

	host := strings.TrimPrefix(ts.URL, "http://")
	validKey := wsNonce()

	tests := []struct {
		name       string
		method     string
		headers    []string
		expectCode int
	}{
		{
			name:       "method is not GET",
			method:     http.MethodPost,
			expectCode: http.StatusBadRequest,
			headers: []string{
				"Host: " + host,
				"Upgrade: websocket",
				"Connection: Upgrade",
				"Sec-WebSocket-Key: " + validKey,
				"Sec-WebSocket-Version: 13",
			},
		},
		{
			name:       "connection header without upgrade",
			method:     http.MethodGet,
			expectCode: http.StatusBadRequest,
			headers: []string{
				"Host: " + host,
				"Upgrade: websocket",
				"Connection: keep-alive",
				"Sec-WebSocket-Key: " + validKey,
				"Sec-WebSocket-Version: 13",
			},
		},
		{
			name:       "missing upgrade header",
			method:     http.MethodGet,
			expectCode: http.StatusBadRequest,
			headers: []string{
				"Host: " + host,
				"Connection: Upgrade",
				"Sec-WebSocket-Key: " + validKey,
				"Sec-WebSocket-Version: 13",
			},
		},
		{
			name:       "unsupported websocket version",
			method:     http.MethodGet,
			expectCode: http.StatusUpgradeRequired,
			headers: []string{
				"Host: " + host,
				"Upgrade: websocket",
				"Connection: Upgrade",
				"Sec-WebSocket-Key: " + validKey,
				"Sec-WebSocket-Version: 12",
			},
		},
		{
			name:       "missing websocket key",
			method:     http.MethodGet,
			expectCode: http.StatusBadRequest,
			headers: []string{
				"Host: " + host,
				"Upgrade: websocket",
				"Connection: Upgrade",
				"Sec-WebSocket-Version: 13",
			},
		},
		{
			name:       "malformed websocket key",
			method:     http.MethodGet,
			expectCode: http.StatusBadRequest,
			headers: []string{
				"Host: " + host,
				"Upgrade: websocket",
				"Connection: Upgrade",
				"Sec-WebSocket-Key: ****not-base64****",
				"Sec-WebSocket-Version: 13",
			},
		},
		{
			name:       "short websocket key",
			method:     http.MethodGet,
			expectCode: http.StatusBadRequest,
			headers: []string{
				"Host: " + host,
				"Upgrade: websocket",
				"Connection: Upgrade",
				"Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString([]byte("short")),
				"Sec-WebSocket-Version: 13",
			},
		},
		{
			name:       "cross origin rejected by default checker",
			method:     http.MethodGet,
			expectCode: http.StatusForbidden,
			headers: []string{
				"Host: " + host,
				"Upgrade: websocket",
				"Connection: Upgrade",
				"Sec-WebSocket-Key: " + validKey,
				"Sec-WebSocket-Version: 13",
				"Origin: http://evil.example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newWsTestClient(t, host)
			client.setReadDeadline(5 * time.Second)
			client.sendRequest(tt.method, tt.headers...)

			resp := client.readResponse(tt.method)
			assert.Equal(t, tt.expectCode, resp.StatusCode, "handshake must be rejected with HTTP status")
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.NotEmpty(t, body)

			// The failed handshake must not have hijacked the connection: a subsequent ordinary
			// request on the same TCP connection has to be served (keep-alive works).
			client.sendPlain("/plain")
			plain := client.readResponse(http.MethodGet)
			assert.Equal(t, http.StatusOK, plain.StatusCode)
			plainBody, err := io.ReadAll(plain.Body)
			require.NoError(t, err)
			assert.Equal(t, "plain ok", string(plainBody))
		})
	}

	select {
	case <-upgraded:
		t.Fatal("no failed handshake may upgrade the connection")
	default:
	}
}

func TestUpgrader_EchoMessages(t *testing.T) {
	t.Parallel()

	upgrader := newTestUpgrader()
	ts := newWSTestServer(t, upgrader, func(c *Context) error {
		ws, err := upgrader.Upgrade(c)
		if err != nil {
			return err
		}
		defer ws.Close()

		messageType, payload, err := ws.ReadMessage()
		if err != nil {
			return nil
		}
		return ws.WriteMessage(messageType, payload)
	})
	host := strings.TrimPrefix(ts.URL, "http://")

	for _, tc := range []struct {
		name     string
		opcode   byte
		payload  string
		expected byte
	}{
		{name: "text", opcode: TextMessage, payload: "hello, echo", expected: TextMessage},
		{name: "binary", opcode: BinaryMessage, payload: "\x00\x01\x02\xff", expected: BinaryMessage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newWsTestClient(t, host)
			client.setReadDeadline(5 * time.Second)
			client.sendRequest(http.MethodGet,
				"Host: "+host,
				"Upgrade: websocket",
				"Connection: Upgrade",
				"Sec-WebSocket-Key: "+wsNonce(),
				"Sec-WebSocket-Version: 13",
			)
			resp := client.readResponse(http.MethodGet)
			require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
			require.NotEmpty(t, resp.Header.Get("Sec-WebSocket-Accept"))

			client.writeFrame(true, tc.opcode, []byte(tc.payload))

			fin, opcode, data, err := client.readFrame()
			require.NoError(t, err)
			assert.True(t, fin)
			assert.Equal(t, tc.expected, opcode)
			assert.Equal(t, tc.payload, string(data))

			// Server closes normally after echoing.
			fin, opcode, data, err = client.readFrame()
			require.NoError(t, err)
			assert.True(t, fin)
			assert.Equal(t, byte(CloseMessage), opcode)
			assert.Equal(t, CloseNormalClosure, closeCodeFromFrame(t, data))

			// Connection is gone after the close handshake.
			_, _, _, err = client.readFrame()
			assert.Error(t, err)
		})
	}
}

func TestUpgrader_CloseCodeNotOverwritten(t *testing.T) {
	t.Parallel()

	t.Run("application close code wins over deferred Close", func(t *testing.T) {
		upgrader := newTestUpgrader()
		ts := newWSTestServer(t, upgrader, func(c *Context) error {
			ws, err := upgrader.Upgrade(c)
			if err != nil {
				return err
			}
			// Handler decides on a specific code; a deferred Close() must not overwrite it.
			if err := ws.WriteControl(
				CloseMessage,
				FormatCloseMessage(ClosePolicyViolation, "policy"),
				time.Now().Add(time.Second),
			); err != nil {
				return err
			}
			return ws.Close()
		})
		host := strings.TrimPrefix(ts.URL, "http://")

		client := newWsTestClient(t, host)
		client.setReadDeadline(5 * time.Second)
		client.sendRequest(http.MethodGet,
			"Host: "+host,
			"Upgrade: websocket",
			"Connection: Upgrade",
			"Sec-WebSocket-Key: "+wsNonce(),
			"Sec-WebSocket-Version: 13",
		)
		require.Equal(t, http.StatusSwitchingProtocols, client.readResponse(http.MethodGet).StatusCode)

		_, opcode, payload, err := client.readFrame()
		require.NoError(t, err)
		require.Equal(t, byte(CloseMessage), opcode)
		assert.Equal(t, ClosePolicyViolation, closeCodeFromFrame(t, payload))

		// Exactly one close frame: the next read must see the closed TCP stream.
		_, _, _, err = client.readFrame()
		assert.Error(t, err)
	})

	t.Run("peer close code is echoed and not overwritten by handler", func(t *testing.T) {
		serverCode := make(chan int, 1)
		upgrader := newTestUpgrader()
		ts := newWSTestServer(t, upgrader, func(c *Context) error {
			ws, err := upgrader.Upgrade(c)
			if err != nil {
				return err
			}
			_, _, readErr := ws.ReadMessage() // returns *CloseError(1001) and echoes it
			var closeErr *CloseError
			if errors.As(readErr, &closeErr) {
				serverCode <- closeErr.Code
			}
			// A careless different code here must be ignored.
			_ = ws.CloseWithCode(CloseTryAgainLater, "retry")
			return nil
		})
		host := strings.TrimPrefix(ts.URL, "http://")

		client := newWsTestClient(t, host)
		client.setReadDeadline(5 * time.Second)
		client.sendRequest(http.MethodGet,
			"Host: "+host,
			"Upgrade: websocket",
			"Connection: Upgrade",
			"Sec-WebSocket-Key: "+wsNonce(),
			"Sec-WebSocket-Version: 13",
		)
		require.Equal(t, http.StatusSwitchingProtocols, client.readResponse(http.MethodGet).StatusCode)

		client.writeClose(CloseGoingAway, "bye")

		_, opcode, payload, err := client.readFrame()
		require.NoError(t, err)
		require.Equal(t, byte(CloseMessage), opcode)
		assert.Equal(t, CloseGoingAway, closeCodeFromFrame(t, payload))
		assert.Equal(t, "bye", string(payload[2:]))

		// No second close frame.
		_, _, _, err = client.readFrame()
		assert.Error(t, err)

		select {
		case code := <-serverCode:
			assert.Equal(t, CloseGoingAway, code)
		case <-time.After(5 * time.Second):
			t.Fatal("server did not observe close")
		}
	})

	t.Run("empty close frame is echoed with an empty payload", func(t *testing.T) {
		upgrader := newTestUpgrader()
		ts := newWSTestServer(t, upgrader, func(c *Context) error {
			ws, err := upgrader.Upgrade(c)
			if err != nil {
				return err
			}
			_, _, _ = ws.ReadMessage() // handles and echoes the status-less close
			return ws.Close()
		})
		host := strings.TrimPrefix(ts.URL, "http://")

		client := newWsTestClient(t, host)
		client.setReadDeadline(5 * time.Second)
		client.sendRequest(http.MethodGet,
			"Host: "+host,
			"Upgrade: websocket",
			"Connection: Upgrade",
			"Sec-WebSocket-Key: "+wsNonce(),
			"Sec-WebSocket-Version: 13",
		)
		require.Equal(t, http.StatusSwitchingProtocols, client.readResponse(http.MethodGet).StatusCode)

		// Status-less close: no payload at all.
		client.writeFrame(true, CloseMessage, nil)

		_, opcode, payload, err := client.readFrame()
		require.NoError(t, err)
		require.Equal(t, byte(CloseMessage), opcode)
		assert.Empty(t, payload, "1005 must never be sent on the wire; echo must be status-less too")

		_, _, _, err = client.readFrame()
		assert.Error(t, err)
	})
}

func TestUpgrader_PingReceivesPong(t *testing.T) {
	t.Parallel()

	upgrader := newTestUpgrader()
	ts := newWSTestServer(t, upgrader, func(c *Context) error {
		ws, err := upgrader.Upgrade(c)
		if err != nil {
			return err
		}
		defer ws.Close()
		_, _, _ = ws.ReadMessage() // returns CloseError after client closes
		return nil
	})
	host := strings.TrimPrefix(ts.URL, "http://")

	client := newWsTestClient(t, host)
	client.setReadDeadline(5 * time.Second)
	client.sendRequest(http.MethodGet,
		"Host: "+host,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Key: "+wsNonce(),
		"Sec-WebSocket-Version: 13",
	)
	require.Equal(t, http.StatusSwitchingProtocols, client.readResponse(http.MethodGet).StatusCode)

	client.writeFrame(true, PingMessage, []byte("ping-data"))

	fin, opcode, payload, err := client.readFrame()
	require.NoError(t, err)
	assert.True(t, fin)
	assert.Equal(t, byte(PongMessage), opcode)
	assert.Equal(t, "ping-data", string(payload))
}

func TestUpgrader_ClientHalfCloseReleasesConnectionAndContext(t *testing.T) {
	t.Parallel()

	serverDone := make(chan error, 1)
	ctxCanceled := make(chan struct{}, 1)

	upgrader := newTestUpgrader()
	ts := newWSTestServer(t, upgrader, func(c *Context) error {
		ws, err := upgrader.Upgrade(c)
		if err != nil {
			return err
		}
		go func() {
			<-ws.Context().Done()
			ctxCanceled <- struct{}{}
		}()
		_, _, readErr := ws.ReadMessage()
		_ = ws.Close()
		serverDone <- readErr
		return nil
	})
	host := strings.TrimPrefix(ts.URL, "http://")

	client := newWsTestClient(t, host)
	client.setReadDeadline(5 * time.Second)
	client.sendRequest(http.MethodGet,
		"Host: "+host,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Key: "+wsNonce(),
		"Sec-WebSocket-Version: 13",
	)
	require.Equal(t, http.StatusSwitchingProtocols, client.readResponse(http.MethodGet).StatusCode)

	// Client stops sending but keeps the read side open (TCP half-close).
	client.halfCloseWrite()

	select {
	case err := <-serverDone:
		assert.ErrorIs(t, err, io.EOF)
	case <-time.After(5 * time.Second):
		t.Fatal("server read did not unblock on client half-close")
	}

	select {
	case <-ctxCanceled:
	case <-time.After(5 * time.Second):
		t.Fatal("websocket request context was not canceled after half-close")
	}

	// Server must have fully closed its side of the socket.
	_, _, _, err := client.readFrame()
	assert.Error(t, err)
}

func TestUpgrader_ContextReleasedOnClose(t *testing.T) {
	t.Parallel()

	ctxCanceled := make(chan struct{}, 1)
	upgrader := newTestUpgrader()
	ts := newWSTestServer(t, upgrader, func(c *Context) error {
		ws, err := upgrader.Upgrade(c)
		if err != nil {
			return err
		}
		go func() {
			<-ws.Context().Done()
			ctxCanceled <- struct{}{}
		}()
		_, _, _ = ws.ReadMessage()
		return ws.Close()
	})
	host := strings.TrimPrefix(ts.URL, "http://")

	client := newWsTestClient(t, host)
	client.setReadDeadline(5 * time.Second)
	client.sendRequest(http.MethodGet,
		"Host: "+host,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Key: "+wsNonce(),
		"Sec-WebSocket-Version: 13",
	)
	require.Equal(t, http.StatusSwitchingProtocols, client.readResponse(http.MethodGet).StatusCode)

	client.writeClose(CloseNormalClosure, "")
	// Drain the echoed close frame and wait for the socket to close.
	for {
		_, opcode, _, err := client.readFrame()
		if err != nil {
			break
		}
		if opcode != CloseMessage {
			t.Fatalf("unexpected opcode %d", opcode)
		}
	}

	select {
	case <-ctxCanceled:
	case <-time.After(5 * time.Second):
		t.Fatal("websocket request context was not canceled after close")
	}
}

func TestUpgrader_ConcurrentUpgrades(t *testing.T) {
	t.Parallel()

	const clients = 32

	upgrader := newTestUpgrader()
	ts := newWSTestServer(t, upgrader, func(c *Context) error {
		ws, err := upgrader.Upgrade(c)
		if err != nil {
			return err
		}
		defer ws.Close()
		messageType, payload, err := ws.ReadMessage()
		if err != nil {
			return nil
		}
		return ws.WriteMessage(messageType, payload)
	})
	host := strings.TrimPrefix(ts.URL, "http://")

	var wg sync.WaitGroup
	errCh := make(chan error, clients)
	start := make(chan struct{})

	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start

			client := newWsTestClient(t, host)
			client.setReadDeadline(10 * time.Second)
			client.sendRequest(http.MethodGet,
				"Host: "+host,
				"Upgrade: websocket",
				"Connection: Upgrade",
				"Sec-WebSocket-Key: "+wsNonce(),
				"Sec-WebSocket-Version: 13",
			)
			resp := client.readResponse(http.MethodGet)
			if resp.StatusCode != http.StatusSwitchingProtocols {
				errCh <- fmt.Errorf("client %d: status %d", i, resp.StatusCode)
				return
			}

			msg := fmt.Sprintf("message-%d", i)
			client.writeFrame(true, TextMessage, []byte(msg))

			fin, opcode, data, err := client.readFrame()
			if err != nil {
				errCh <- fmt.Errorf("client %d read echo: %w", i, err)
				return
			}
			if !fin || opcode != TextMessage || string(data) != msg {
				errCh <- fmt.Errorf("client %d bad echo: fin=%v opcode=%d data=%q", i, fin, opcode, data)
				return
			}

			client.writeClose(CloseNormalClosure, "")
			// Drain server frames until the socket is closed.
			for {
				if _, _, _, err := client.readFrame(); err != nil {
					return
				}
			}
		}(i)
	}

	close(start)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("concurrent upgrades did not finish in time")
	}
	close(errCh)
	for err := range errCh {
		assert.NoError(t, err)
	}
}

func TestStartConfig_ShutdownReleasesWebSocketConnections(t *testing.T) {
	t.Parallel()

	e := New()
	e.GET("/plain", func(c *Context) error {
		return c.String(http.StatusOK, "plain ok")
	})

	sessionReleased := make(chan error, 1)
	ready := make(chan struct{}, 1)
	upgrader := &Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	e.GET("/ws", func(c *Context) error {
		ws, err := upgrader.Upgrade(c)
		if err != nil {
			return err
		}
		ready <- struct{}{}
		// Long-lived session: block reading until the socket is torn down by server shutdown.
		for {
			if _, _, readErr := ws.ReadMessage(); readErr != nil {
				sessionReleased <- ws.Context().Err()
				_ = ws.Close()
				return nil
			}
		}
	})

	addrChan := make(chan string)
	errCh := make(chan error)
	// Large graceful timeout: the websocket session must be released actively, not by waiting for
	// the overall shutdown deadline to expire.
	ctx, shutdown := stdContext.WithCancel(stdContext.Background())
	defer shutdown()
	go func() {
		errCh <- (&StartConfig{
			Address:         ":0",
			GracefulTimeout: 30 * time.Second,
			ListenerAddrFunc: func(addr net.Addr) {
				addrChan <- addr.String()
			},
		}).Start(ctx, e)
	}()

	var addr string
	select {
	case addr = <-addrChan:
	case err := <-errCh:
		t.Fatalf("server failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not start")
	}

	// Ordinary HTTP traffic is unaffected by the hijack tracking.
	code, body, err := doGet(fmt.Sprintf("http://%s/plain", addr))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "plain ok", body)

	client := newWsTestClient(t, addr)
	client.setReadDeadline(5 * time.Second)
	client.sendRequest(http.MethodGet,
		"Host: "+addr,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Key: "+wsNonce(),
		"Sec-WebSocket-Version: 13",
	)
	require.Equal(t, http.StatusSwitchingProtocols, client.readResponse(http.MethodGet).StatusCode)
	<-ready

	started := time.Now()
	shutdown()

	// Client observes the graceful GoingAway close frame rather than a silent/reset connection.
	_, opcode, payload, err := client.readFrame()
	require.NoError(t, err)
	require.Equal(t, byte(CloseMessage), opcode)
	assert.Equal(t, CloseGoingAway, closeCodeFromFrame(t, payload))

	select {
	case ctxErr := <-sessionReleased:
		assert.ErrorIs(t, ctxErr, stdContext.Canceled, "websocket request context must be canceled on shutdown")
	case <-time.After(5 * time.Second):
		t.Fatal("websocket handler was not released by shutdown")
	}

	select {
	case err := <-errCh:
		assert.True(t, err == nil || errors.Is(err, http.ErrServerClosed), "unexpected start error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after shutdown")
	}
	assert.Less(t, time.Since(started), 5*time.Second,
		"shutdown must close hijacked websockets immediately instead of waiting for the 30s grace period")
}
