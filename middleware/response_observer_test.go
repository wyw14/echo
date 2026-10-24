// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2015 LabStack LLC and Echo contributors

package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResponseObserver_ForwardsLifecycleEventsWithContext(t *testing.T) {
	e := echo.New()

	var mu sync.Mutex
	var events []echo.ResponseHookInfo
	var seenPath string
	e.Use(ResponseObserver(func(c *echo.Context, event echo.ResponseHookInfo) {
		mu.Lock()
		defer mu.Unlock()
		seenPath = c.Path()
		events = append(events, event)
	}))
	e.GET("/items", func(c *echo.Context) error {
		return c.String(http.StatusCreated, "hi")
	})

	req := httptest.NewRequest(http.MethodGet, "/items", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "hi", rec.Body.String())

	// connection_closed is dispatched by the watcher goroutine when Echo finishes serving.
	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(events) == 4 && seenPath == "/items"
	}, 3*time.Second, 5*time.Millisecond)

	mu.Lock()
	kinds := make([]echo.ResponseHookEvent, 0, len(events))
	for _, ev := range events {
		kinds = append(kinds, ev.Event)
	}
	assert.Equal(t, []echo.ResponseHookEvent{
		echo.ResponseEventHeaderCommitted,
		echo.ResponseEventFirstByte,
		echo.ResponseEventHandlerDone,
		echo.ResponseEventConnectionClosed,
	}, kinds)
	assert.Equal(t, http.StatusCreated, events[0].Status)
	assert.Equal(t, int64(2), events[1].Size)
	mu.Unlock()
}

func TestResponseObserver_Skipped(t *testing.T) {
	e := echo.New()

	called := 0
	e.Use(ResponseObserverWithConfig(ResponseObserverConfig{
		Skipper: func(c *echo.Context) bool { return true },
		OnEvent: func(c *echo.Context, event echo.ResponseHookInfo) {
			called++
		},
	}))
	e.GET("/skip", func(c *echo.Context) error { return c.String(http.StatusOK, "x") })

	req := httptest.NewRequest(http.MethodGet, "/skip", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, 0, called)
}

func TestResponseObserver_MissingCallback(t *testing.T) {
	_, err := ResponseObserverConfig{}.ToMiddleware()
	require.Error(t, err)
	assert.Panics(t, func() {
		ResponseObserverWithConfig(ResponseObserverConfig{})
	})
}

func TestResponseObserver_PanickingCallbackDoesNotChangeResponse(t *testing.T) {
	e := echo.New()
	e.Use(ResponseObserver(func(c *echo.Context, event echo.ResponseHookInfo) {
		panic("observer boom")
	}))
	e.GET("/panic", func(c *echo.Context) error {
		return c.String(http.StatusTeapot, "still served")
	})

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	rec := httptest.NewRecorder()
	assert.NotPanics(t, func() {
		e.ServeHTTP(rec, req)
	})
	assert.Equal(t, http.StatusTeapot, rec.Code)
	assert.Equal(t, "still served", rec.Body.String())
}
