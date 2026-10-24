// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2015 LabStack LLC and Echo contributors

package echo

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hookEventRecorder collects ResponseHookInfo per request, correlating requests with the
// X-Req-Id request header (client-side context values are not propagated over HTTP).
type hookEventRecorder struct {
	mu     sync.Mutex
	events map[string][]ResponseHookInfo
}

func (h *hookEventRecorder) record(info ResponseHookInfo) {
	id := ""
	if info.Request != nil {
		id = info.Request.Header.Get("X-Req-Id")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.events == nil {
		h.events = map[string][]ResponseHookInfo{}
	}
	h.events[id] = append(h.events[id], info)
}

func (h *hookEventRecorder) snapshot(id string) []ResponseHookInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]ResponseHookInfo(nil), h.events[id]...)
}

func (h *hookEventRecorder) waitFor(t *testing.T, id string, n int) []ResponseHookInfo {
	t.Helper()
	assert.Eventually(t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return len(h.events[id]) >= n
	}, 5*time.Second, 5*time.Millisecond, "waiting for %d events for request %q", n, id)
	return h.snapshot(id)
}

func eventKinds(events []ResponseHookInfo) []ResponseHookEvent {
	kinds := make([]ResponseHookEvent, 0, len(events))
	for _, ev := range events {
		kinds = append(kinds, ev.Event)
	}
	return kinds
}

func findEvent(events []ResponseHookInfo, kind ResponseHookEvent) (ResponseHookInfo, bool) {
	for _, ev := range events {
		if ev.Event == kind {
			return ev, true
		}
	}
	return ResponseHookInfo{}, false
}

func newHookEcho(rec *hookEventRecorder) *Echo {
	e := New()
	e.AddResponseHook(rec.record)
	return e
}

func hookRequest(ctx context.Context, method, url string, headers map[string]string) *http.Request {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		panic(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// --- Response level (unit) -------------------------------------------------

func TestResponseHook_WriterLifecycle(t *testing.T) {
	e := New()
	rec := httptest.NewRecorder()
	res := NewResponse(rec, e.Logger)

	var mu sync.Mutex
	var events []ResponseHookInfo
	res.AddResponseHook(func(info ResponseHookInfo) {
		mu.Lock()
		events = append(events, info)
		mu.Unlock()
	})

	res.WriteHeader(http.StatusCreated)
	_, err := res.Write([]byte("hello"))
	require.NoError(t, err)
	_, err = res.Write([]byte(" world"))
	require.NoError(t, err)
	res.Flush()

	// A duplicate WriteHeader must be ignored and must not produce another commit event.
	res.WriteHeader(http.StatusBadRequest)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 3)
	assert.Equal(t, []ResponseHookEvent{
		ResponseEventHeaderCommitted,
		ResponseEventFirstByte,
		ResponseEventFlush,
	}, eventKinds(events))

	assert.Equal(t, http.StatusCreated, events[0].Status)
	assert.True(t, events[0].Committed)
	assert.Equal(t, int64(0), events[0].Size)

	assert.Equal(t, int64(5), events[1].Size) // first byte event fires exactly once
	assert.Equal(t, int64(11), events[2].Size)
	assert.True(t, events[2].Committed)

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "hello world", rec.Body.String())
}

func TestResponseHook_PanicIsolatedAndSlowHookKeepsStatus(t *testing.T) {
	e := New()
	rec := httptest.NewRecorder()
	res := NewResponse(rec, e.Logger)

	var mu sync.Mutex
	var good []ResponseHookInfo

	// First hook panics: it must be recovered and neither change the response nor stop the
	// second hook from running.
	res.AddResponseHook(func(ResponseHookInfo) { panic("boom") })
	res.AddResponseHook(func(info ResponseHookInfo) {
		if info.Event == ResponseEventHeaderCommitted {
			time.Sleep(40 * time.Millisecond) // slow observer
		}
		mu.Lock()
		good = append(good, info)
		mu.Unlock()
	})

	start := time.Now()
	require.NotPanics(t, func() {
		res.WriteHeader(http.StatusAccepted)
		_, werr := res.Write([]byte("ok"))
		require.NoError(t, werr)
	})
	elapsed := time.Since(start)

	assert.Equal(t, http.StatusAccepted, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())
	assert.GreaterOrEqual(t, elapsed, 35*time.Millisecond) // slow hook is synchronous ...
	// ... but delivery continued for every event despite the panicking hook.
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, good, 2)
	assert.Equal(t, ResponseEventHeaderCommitted, good[0].Event)
	assert.Equal(t, ResponseEventFirstByte, good[1].Event)
}

// --- Empty responses --------------------------------------------------------

func TestResponseHook_EmptyResponse(t *testing.T) {
	rec := &hookEventRecorder{}
	e := newHookEcho(rec)
	e.GET("/empty", func(c *Context) error { return nil })
	srv := httptest.NewServer(e)
	defer srv.Close()

	req := hookRequest(context.Background(), http.MethodGet, srv.URL+"/empty", map[string]string{"X-Req-Id": "empty"})
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, body)

	events := rec.waitFor(t, "empty", 2)
	assert.Equal(t, []ResponseHookEvent{ResponseEventHandlerDone, ResponseEventConnectionClosed}, eventKinds(events))

	done, ok := findEvent(events, ResponseEventHandlerDone)
	require.True(t, ok)
	assert.False(t, done.Committed, "nothing was written, so headers were not committed by Echo")
	assert.Equal(t, http.StatusOK, done.Status, "effective status is resolved like net/http would")
	assert.Equal(t, int64(0), done.Size)
	assert.NoError(t, done.Err)

	closed, ok := findEvent(events, ResponseEventConnectionClosed)
	require.True(t, ok)
	assert.Equal(t, http.StatusOK, closed.Status)
}

func TestResponseHook_NoContentHasCommitButNoByte(t *testing.T) {
	rec := &hookEventRecorder{}
	e := newHookEcho(rec)
	e.GET("/204", func(c *Context) error { return c.NoContent(http.StatusNoContent) })
	srv := httptest.NewServer(e)
	defer srv.Close()

	req := hookRequest(context.Background(), http.MethodGet, srv.URL+"/204", map[string]string{"X-Req-Id": "204"})
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	events := rec.waitFor(t, "204", 3)
	assert.Equal(t, []ResponseHookEvent{
		ResponseEventHeaderCommitted,
		ResponseEventHandlerDone,
		ResponseEventConnectionClosed,
	}, eventKinds(events))
	assert.Equal(t, http.StatusNoContent, events[0].Status)
	assert.Equal(t, int64(0), events[0].Size)

	_, hasFirstByte := findEvent(events, ResponseEventFirstByte)
	assert.False(t, hasFirstByte)
}

func TestResponseHook_HandlerErrorReported(t *testing.T) {
	rec := &hookEventRecorder{}
	e := newHookEcho(rec)
	e.GET("/fail", func(c *Context) error { return ErrNotFound })
	srv := httptest.NewServer(e)
	defer srv.Close()

	req := hookRequest(context.Background(), http.MethodGet, srv.URL+"/fail", map[string]string{"X-Req-Id": "fail"})
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.NotEmpty(t, body)

	events := rec.waitFor(t, "fail", 4)
	assert.Equal(t, []ResponseHookEvent{
		ResponseEventHeaderCommitted,
		ResponseEventFirstByte,
		ResponseEventHandlerDone,
		ResponseEventConnectionClosed,
	}, eventKinds(events))
	done, _ := findEvent(events, ResponseEventHandlerDone)
	assert.Equal(t, http.StatusNotFound, done.Status)
	assert.ErrorIs(t, done.Err, ErrNotFound)
}

// --- Disconnect ---------------------------------------------------------------

func TestResponseHook_ClientDisconnectReportsCanceledClose(t *testing.T) {
	rec := &hookEventRecorder{}
	e := newHookEcho(rec)
	started := make(chan struct{})
	e.GET("/hang", func(c *Context) error {
		close(started)
		<-c.Request().Context().Done()
		// Stay alive briefly after observing the cancellation so the close watcher deterministically
		// emits connection_closed from its live-snapshot path while the handler is still running.
		time.Sleep(150 * time.Millisecond)
		return nil
	})
	srv := httptest.NewServer(e)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := hookRequest(ctx, http.MethodGet, srv.URL+"/hang", map[string]string{"X-Req-Id": "hang"})
	clientDone := make(chan struct{})
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		close(clientDone)
	}()

	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("handler never started")
	}
	cancel()
	select {
	case <-clientDone:
	case <-time.After(3 * time.Second):
		t.Fatal("client did not return after cancel")
	}

	// Close must fire (with cancellation) before handler-done, since the handler keeps running
	// for a short while after observing the request context cancellation.
	events := rec.waitFor(t, "hang", 2)
	require.Equal(t, []ResponseHookEvent{
		ResponseEventConnectionClosed,
		ResponseEventHandlerDone,
	}, eventKinds(events))
	assert.ErrorIs(t, events[0].Err, context.Canceled)
	assert.False(t, events[0].Committed, "no status code was sent before the disconnect")
	assert.Equal(t, int64(0), events[0].Size)
	assert.NoError(t, events[1].Err, "handler unblocks and returns nil")
}

// --- Concurrency ---------------------------------------------------------------

func TestResponseHook_ConcurrentRequests(t *testing.T) {
	rec := &hookEventRecorder{}
	e := newHookEcho(rec)
	payload := bytes.Repeat([]byte("x"), 128)
	e.GET("/json", func(c *Context) error { return c.JSON(http.StatusOK, map[string]string{"ok": "true"}) })
	e.GET("/blob", func(c *Context) error { return c.Blob(http.StatusOK, MIMEOctetStream, payload) })
	e.GET("/204", func(c *Context) error { return c.NoContent(http.StatusNoContent) })
	srv := httptest.NewServer(e)
	defer srv.Close()

	const n = 40
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("c-%03d", i)
			path := "/json"
			wantStatus := http.StatusOK
			want := []ResponseHookEvent{
				ResponseEventHeaderCommitted, ResponseEventFirstByte,
				ResponseEventHandlerDone, ResponseEventConnectionClosed,
			}
			if i%3 == 1 {
				path = "/blob"
			}
			if i%3 == 2 {
				path = "/204"
				wantStatus = http.StatusNoContent
				want = []ResponseHookEvent{
					ResponseEventHeaderCommitted,
					ResponseEventHandlerDone,
					ResponseEventConnectionClosed,
				}
			}
			req := hookRequest(context.Background(), http.MethodGet, srv.URL+path, map[string]string{"X-Req-Id": id})
			resp, err := http.DefaultClient.Do(req)
			if !assert.NoError(t, err, "request %s", id) {
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()

			events := rec.waitFor(t, id, len(want))
			assert.Equal(t, want, eventKinds(events), "request %s", id)
			for _, ev := range events {
				assert.NotNil(t, ev.Request, "request %s event %s", id, ev.Event)
				switch ev.Event {
				case ResponseEventHeaderCommitted, ResponseEventHandlerDone:
					assert.Equal(t, wantStatus, ev.Status, "request %s event %s", id, ev.Event)
				}
			}
		}()
	}
	wg.Wait()
}

// --- Streaming over HTTP/1.1 ---------------------------------------------------

func TestResponseHook_StreamingFlushEventsAndIncrementalDelivery(t *testing.T) {
	rec := &hookEventRecorder{}
	e := newHookEcho(rec)
	proceed := make(chan struct{})
	e.GET("/sse", func(c *Context) error {
		c.Response().Header().Set(HeaderContentType, "text/event-stream")
		c.Response().WriteHeader(http.StatusOK)
		for i := 0; i < 3; i++ {
			if _, err := c.Response().Write([]byte("data: payload\n\n")); err != nil {
				return err
			}
			if err := http.NewResponseController(c.Response()).Flush(); err != nil {
				return err
			}
			time.Sleep(50 * time.Millisecond)
		}
		// Stay alive after flushing so the client proves it received chunks while the handler was
		// still running.
		<-proceed
		return nil
	})
	srv := httptest.NewServer(e)
	defer srv.Close()

	req := hookRequest(context.Background(), http.MethodGet, srv.URL+"/sse", map[string]string{"X-Req-Id": "sse"})
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, "text/event-stream", resp.Header.Get(HeaderContentType))

	reader := bufio.NewReader(resp.Body)
	var lines []string
	deadline := time.Now().Add(3 * time.Second)
	for len(lines) < 3 && time.Now().Before(deadline) {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("unexpected read error: %v", err)
		}
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	require.Len(t, lines, 3, "client must receive every flushed chunk incrementally")

	// Events observed while the handler is still blocked: one first-byte and three flushes.
	assert.Eventually(t, func() bool {
		events := rec.snapshot("sse")
		_, hasFirstByte := findEvent(events, ResponseEventFirstByte)
		flushes := 0
		for _, ev := range events {
			if ev.Event == ResponseEventFlush {
				flushes++
			}
		}
		return hasFirstByte && flushes == 3
	}, 3*time.Second, 5*time.Millisecond)

	events := rec.snapshot("sse")
	firstByte, _ := findEvent(events, ResponseEventFirstByte)
	assert.Equal(t, int64(len("data: payload\n\n")), firstByte.Size)
	assert.True(t, firstByte.Committed)
	close(proceed)

	// commit, first byte, 3x flush, handler done, connection close
	events = rec.waitFor(t, "sse", 7)
	assert.Equal(t, []ResponseHookEvent{
		ResponseEventHeaderCommitted,
		ResponseEventFirstByte,
		ResponseEventFlush,
		ResponseEventFlush,
		ResponseEventFlush,
		ResponseEventHandlerDone,
		ResponseEventConnectionClosed,
	}, eventKinds(events))
}

// --- HTTP/2 ---------------------------------------------------------------------

func TestResponseHook_HTTP2Streaming(t *testing.T) {
	rec := &hookEventRecorder{}
	e := newHookEcho(rec)
	proceed := make(chan struct{})
	e.GET("/h2", func(c *Context) error {
		require.Equal(t, 2, c.Request().ProtoMajor)
		c.Response().Header().Set(HeaderContentType, "text/event-stream")
		c.Response().WriteHeader(http.StatusOK)
		for i := 0; i < 2; i++ {
			_, _ = c.Response().Write([]byte("data: h2\n\n"))
			c.Response().(http.Flusher).Flush()
			time.Sleep(50 * time.Millisecond)
		}
		<-proceed
		return nil
	})

	srv := httptest.NewUnstartedServer(e)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	client := srv.Client()
	req := hookRequest(context.Background(), http.MethodGet, srv.URL+"/h2", map[string]string{"X-Req-Id": "h2"})
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, "HTTP/2.0", resp.Proto)
	assert.Equal(t, "text/event-stream", resp.Header.Get(HeaderContentType))

	reader := bufio.NewReader(resp.Body)
	var lines []string
	deadline := time.Now().Add(3 * time.Second)
	for len(lines) < 2 && time.Now().Before(deadline) {
		line, rerr := reader.ReadString('\n')
		require.NoError(t, rerr)
		if strings.TrimSpace(line) != "" {
			lines = append(lines, strings.TrimSpace(line))
		}
	}
	assert.Equal(t, []string{"data: h2", "data: h2"}, lines)

	// Flush events arrive over HTTP/2 with the same semantics.
	assert.Eventually(t, func() bool {
		flushes := 0
		for _, ev := range rec.snapshot("h2") {
			if ev.Event == ResponseEventFlush {
				flushes++
			}
		}
		return flushes == 2
	}, 3*time.Second, 5*time.Millisecond)

	close(proceed)
	events := rec.waitFor(t, "h2", 6) // commit, first byte, 2x flush, done, closed
	assert.Equal(t, []ResponseHookEvent{
		ResponseEventHeaderCommitted,
		ResponseEventFirstByte,
		ResponseEventFlush,
		ResponseEventFlush,
		ResponseEventHandlerDone,
		ResponseEventConnectionClosed,
	}, eventKinds(events))
}

// --- HEAD ------------------------------------------------------------------------

func TestResponseHook_HeadRequestReportsSizeWithoutBytes(t *testing.T) {
	rec := &hookEventRecorder{}
	e := NewWithConfig(Config{
		Router:        NewRouter(RouterConfig{AutoHandleHEAD: true}),
		ResponseHooks: []ResponseHookFunc{rec.record},
	})
	e.GET("/head", func(c *Context) error { return c.String(http.StatusOK, "head-body") })
	srv := httptest.NewServer(e)
	defer srv.Close()

	req := hookRequest(context.Background(), http.MethodHead, srv.URL+"/head", map[string]string{"X-Req-Id": "head"})
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int64(9), resp.ContentLength)

	events := rec.waitFor(t, "head", 3)
	assert.Equal(t, []ResponseHookEvent{
		ResponseEventHeaderCommitted,
		ResponseEventHandlerDone,
		ResponseEventConnectionClosed,
	}, eventKinds(events))
	assert.Equal(t, int64(0), events[0].Size)
	assert.Equal(t, int64(9), events[1].Size, "handler-done reports the size GET would have written")
	_, hasFirstByte := findEvent(events, ResponseEventFirstByte)
	assert.False(t, hasFirstByte)
}
