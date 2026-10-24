// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2015 LabStack LLC and Echo contributors

package echo_test

// Gzip middleware lives in a package importing echo, so these integration tests use the external
// echo_test test package to avoid an import cycle in the internal package echo tests.

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type extHookRecorder struct {
	mu     sync.Mutex
	events map[string][]echo.ResponseHookInfo
}

func (h *extHookRecorder) record(info echo.ResponseHookInfo) {
	id := ""
	if info.Request != nil {
		id = info.Request.Header.Get("X-Req-Id")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.events == nil {
		h.events = map[string][]echo.ResponseHookInfo{}
	}
	h.events[id] = append(h.events[id], info)
}

func (h *extHookRecorder) waitFor(t *testing.T, id string, n int) []echo.ResponseHookInfo {
	t.Helper()
	assert.Eventually(t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return len(h.events[id]) >= n
	}, 5*time.Second, 5*time.Millisecond)
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]echo.ResponseHookInfo(nil), h.events[id]...)
}

func extKinds(events []echo.ResponseHookInfo) []echo.ResponseHookEvent {
	kinds := make([]echo.ResponseHookEvent, 0, len(events))
	for _, ev := range events {
		kinds = append(kinds, ev.Event)
	}
	return kinds
}

func TestResponseHook_GzipSmallBodySentUncompressed(t *testing.T) {
	rec := &extHookRecorder{}
	e := echo.New()
	e.AddResponseHook(rec.record)
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{MinLength: 1024}))
	small := strings.Repeat("a", 50)
	e.GET("/small", func(c *echo.Context) error { return c.String(http.StatusOK, small) })
	srv := httptest.NewServer(e)
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/small", nil)
	require.NoError(t, err)
	req.Header.Set("X-Req-Id", "small")
	req.Header.Set(echo.HeaderAcceptEncoding, "gzip")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	require.NoError(t, resp.Body.Close())

	assert.Empty(t, resp.Header.Get(echo.HeaderContentEncoding))
	assert.Equal(t, small, string(body))

	events := rec.waitFor(t, "small", 4)
	assert.Equal(t, []echo.ResponseHookEvent{
		echo.ResponseEventHeaderCommitted,
		echo.ResponseEventFirstByte,
		echo.ResponseEventHandlerDone,
		echo.ResponseEventConnectionClosed,
	}, extKinds(events))
	assert.Equal(t, int64(50), events[1].Size, "buffered small body reaches Echo uncompressed")
}

func TestResponseHook_GzipLargeBodyCompressed(t *testing.T) {
	rec := &extHookRecorder{}
	e := echo.New()
	e.AddResponseHook(rec.record)
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{MinLength: 1024}))
	payload := bytes.Repeat([]byte("echo-compress-"), 300) // 4200 bytes
	e.GET("/large", func(c *echo.Context) error {
		return c.Blob(http.StatusOK, echo.MIMETextPlain, payload)
	})
	srv := httptest.NewServer(e)
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/large", nil)
	require.NoError(t, err)
	req.Header.Set("X-Req-Id", "large")
	req.Header.Set(echo.HeaderAcceptEncoding, "gzip")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, "gzip", resp.Header.Get(echo.HeaderContentEncoding))
	gz, err := gzip.NewReader(resp.Body)
	require.NoError(t, err)
	body, err := io.ReadAll(gz)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, payload, body)

	events := rec.waitFor(t, "large", 4)
	assert.Equal(t, []echo.ResponseHookEvent{
		echo.ResponseEventHeaderCommitted,
		echo.ResponseEventFirstByte,
		echo.ResponseEventHandlerDone,
		echo.ResponseEventConnectionClosed,
	}, extKinds(events))
	assert.Equal(t, http.StatusOK, events[1].Status)
	assert.Greater(t, events[1].Size, int64(0))
	assert.Less(t, events[1].Size, int64(len(payload)), "observed bytes are the compressed wire bytes")
}
