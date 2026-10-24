// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2015 LabStack LLC and Echo contributors

package echo

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
)

// Response wraps an http.ResponseWriter and implements its interface to be used
// by an HTTP handler to construct an HTTP response.
// See: https://golang.org/pkg/net/http/#ResponseWriter
type Response struct {
	http.ResponseWriter
	logger *slog.Logger
	// beforeFuncs are functions that are called just before the response (status) is written. Happens only once, during WriteHeader call.
	beforeFuncs []func()
	// afterFuncs are functions that are called just after the response is written. During every `Write` method call.
	afterFuncs []func()
	Status     int
	Size       int64
	Committed  bool

	// hookBus holds the per-request response lifecycle observers and the close watcher state.
	// It is nil unless at least one hook is registered, keeping the unobserved hot path free of
	// allocations and locks. Replaced with a fresh bus on every reset.
	hookBus *responseHookBus
	// reqCtx/hookReq are the current request context/request, set by initHooks in ServeHTTP so
	// that per-request AddResponseHook (e.g. from a middleware) can start the connection watcher.
	reqCtx  context.Context
	hookReq *http.Request
}

// NewResponse creates a new instance of Response.
func NewResponse(w http.ResponseWriter, logger *slog.Logger) (r *Response) {
	return &Response{ResponseWriter: w, logger: logger}
}

// Before registers a function which is called just before the response (status) is written.
func (r *Response) Before(fn func()) {
	r.beforeFuncs = append(r.beforeFuncs, fn)
}

// After registers a function which is called just after the response is written.
func (r *Response) After(fn func()) {
	r.afterFuncs = append(r.afterFuncs, fn)
}

// WriteHeader sends an HTTP response header with status code. If WriteHeader is
// not called explicitly, the first call to Write will trigger an implicit
// WriteHeader(http.StatusOK). Thus explicit calls to WriteHeader are mainly
// used to send error codes.
func (r *Response) WriteHeader(code int) {
	if r.Committed {
		r.logger.Error("echo: response already written to client")
		return
	}
	// Record the chosen status before beforeFuncs run (they may change it) and do so under the
	// hook lock so a disconnect watcher snapshotting a live response can not race the update.
	if bus := r.hookBus; bus != nil {
		bus.mu.Lock()
		r.Status = code
		bus.mu.Unlock()
	} else {
		r.Status = code
	}
	for _, fn := range r.beforeFuncs {
		fn()
	}
	r.ResponseWriter.WriteHeader(r.Status)
	// The status is on the wire now: mark committed and notify observers only afterwards. Because
	// the event is dispatched after the transport write, a slow or panicking hook can neither
	// delay the header nor change the status code.
	bus := r.hookBus
	if bus != nil {
		bus.mu.Lock()
		r.Committed = true
		info := bus.snapshot(r, ResponseEventHeaderCommitted, nil)
		bus.mu.Unlock()
		bus.dispatch(info)
	} else {
		r.Committed = true
	}
}

// Write writes the data to the connection as part of an HTTP reply.
func (r *Response) Write(b []byte) (n int, err error) {
	if !r.Committed {
		// Implicit 200 OK, matching net/http behavior. Resolve the code under the hook lock so
		// the Status read is synchronized with the disconnect watcher.
		code := http.StatusOK
		if bus := r.hookBus; bus != nil {
			bus.mu.Lock()
			if r.Status != 0 {
				code = r.Status
			}
			bus.mu.Unlock()
		} else if r.Status != 0 {
			code = r.Status
		}
		r.WriteHeader(code)
	}
	n, err = r.ResponseWriter.Write(b)

	// The exactly-once first-byte event is decided together with the Size update under the hook
	// lock, after bytes have already reached the underlying writer.
	bus := r.hookBus
	var firstByteInfo ResponseHookInfo
	dispatchFirstByte := false
	if bus != nil {
		bus.mu.Lock()
		r.Size += int64(n)
		if n > 0 && !bus.firstByte {
			bus.firstByte = true
			firstByteInfo = bus.snapshot(r, ResponseEventFirstByte, err)
			dispatchFirstByte = true
		}
		bus.mu.Unlock()
	} else {
		r.Size += int64(n)
	}
	for _, fn := range r.afterFuncs {
		fn()
	}
	if dispatchFirstByte {
		bus.dispatch(firstByteInfo)
	}
	return
}

// Flush implements the http.Flusher interface to allow an HTTP handler to flush
// buffered data to the client.
// See [http.Flusher](https://golang.org/pkg/net/http/#Flusher)
func (r *Response) Flush() {
	err := http.NewResponseController(r.ResponseWriter).Flush()
	if err != nil && errors.Is(err, http.ErrNotSupported) {
		panic(fmt.Errorf("echo: response writer %T does not support flushing (http.Flusher interface)", r.ResponseWriter))
	}
	// Notify only after the underlying flush succeeded: observers can never alter the streaming
	// protocol behavior, and HTTP/2 flush semantics are inherited unchanged from the transport.
	if err == nil {
		r.emitEvent(ResponseEventFlush, nil)
	}
}

// Hijack implements the http.Hijacker interface to allow an HTTP handler to
// take over the connection.
// This method is relevant to Websocket connection upgrades, proxis, and other advanced use cases.
// See [http.Hijacker](https://golang.org/pkg/net/http/#Hijacker)
func (r *Response) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	// newer code should do response hijacking like that
	// http.NewResponseController(responseWriter).Hijack()
	//
	// but there are older libraries that are not aware of `http.NewResponseController` and try to hijack directly
	// `hj, ok := resp.(http.Hijacker)` <-- which would fail without Response directly implementing Hijack method
	// so for that purpose we need to implement http.Hijacker interface
	return http.NewResponseController(r.ResponseWriter).Hijack()
}

// Unwrap returns the original http.ResponseWriter.
// ResponseController can be used to access the original http.ResponseWriter.
// See [https://go.dev/blog/go1.20]
func (r *Response) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func (r *Response) reset(w http.ResponseWriter) {
	r.beforeFuncs = nil
	r.afterFuncs = nil
	r.ResponseWriter = w
	r.Size = 0
	r.Status = http.StatusOK
	r.Committed = false
	// Detach the previous request's observer bus. A lingering close watcher keeps its own old bus
	// reference and the immutable final snapshot, so it can never observe the next pooled request.
	r.hookBus = nil
	r.reqCtx = nil
	r.hookReq = nil
}

// UnwrapResponse unwraps given ResponseWriter to return contexts original Echo Response. rw has to implement
// following method `Unwrap() http.ResponseWriter`
func UnwrapResponse(rw http.ResponseWriter) (*Response, error) {
	for {
		switch t := rw.(type) {
		case *Response:
			return t, nil
		case interface{ Unwrap() http.ResponseWriter }:
			rw = t.Unwrap()
			continue
		default:
			return nil, errors.New("ResponseWriter does not implement 'Unwrap() http.ResponseWriter' interface or unwrap to *echo.Response")
		}
	}
}

// delayedStatusWriter is a wrapper around http.ResponseWriter that delays writing the status code until first Write is called.
// This allows (global) error handler to decide correct status code to be sent to the client.
type delayedStatusWriter struct {
	http.ResponseWriter
	committed bool
	status    int
}

func (w *delayedStatusWriter) WriteHeader(statusCode int) {
	// in case something else writes status code explicitly before us we need mark response committed
	w.committed = true
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *delayedStatusWriter) Write(data []byte) (int, error) {
	if !w.committed {
		w.committed = true
		if w.status == 0 {
			w.status = http.StatusOK
		}
		w.ResponseWriter.WriteHeader(w.status)
	}
	return w.ResponseWriter.Write(data)
}

func (w *delayedStatusWriter) Flush() {
	err := http.NewResponseController(w.ResponseWriter).Flush()
	if err != nil && errors.Is(err, http.ErrNotSupported) {
		panic(errors.New("response writer flushing is not supported"))
	}
}

func (w *delayedStatusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func (w *delayedStatusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// headResponseWriter captures the response that a GET handler would produce for a
// rewritten HEAD request, suppresses the body, and preserves response metadata.
//
// The writer buffers status until the downstream handler returns, so it
// can compute a Content-Length value from the number of body bytes that would have
// been written by the GET handler. If the handler already sets Content-Length
// explicitly, that value is preserved.
//
// Flush is intentionally a no-op because emitting headers early would prevent
// finalizing Content-Length after the handler completes.
type headResponseWriter struct {
	rw          http.ResponseWriter
	status      int
	wroteStatus bool
	bodyBytes   int64
}

func (w *headResponseWriter) Header() http.Header {
	return w.rw.Header()
}

func (w *headResponseWriter) WriteHeader(code int) {
	if w.wroteStatus {
		return
	}
	w.wroteStatus = true
	w.status = code
	if r, err := UnwrapResponse(w.rw); err == nil {
		r.setCommitted(true)
	}
}

func (w *headResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteStatus {
		w.WriteHeader(http.StatusOK)
	}
	w.bodyBytes += int64(len(b))
	return len(b), nil
}

func (w *headResponseWriter) Flush() {
	// No-op on purpose. A HEAD response has no body, and flushing early would
	// commit headers before Content-Length can be finalized.
}

func (w *headResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.rw).Hijack()
}

func (w *headResponseWriter) Unwrap() http.ResponseWriter {
	return w.rw
}

func (w *headResponseWriter) commit() {
	dst := w.rw.Header()
	if w.wroteStatus &&
		dst.Get(HeaderContentLength) == "" &&
		dst.Get("Transfer-Encoding") == "" &&
		!statusMustNotHaveBody(w.status) {
		dst.Set(HeaderContentLength, strconv.FormatInt(w.bodyBytes, 10))
	}

	// "commit" the Response only when the headers were written otherwise the Echo errorhandler cannot properly handle errors
	if w.wroteStatus {
		// WriteHeader set Committed=true early so route middleware could observe it.
		// Reset it here so *Response.WriteHeader can fire beforeFuncs and reach the transport.
		if r, err := UnwrapResponse(w.rw); err == nil {
			r.setCommitted(false)
		}
		w.rw.WriteHeader(w.status)
		// Fire After hooks on the underlying *Response so that middleware such as
		// loggers and metrics collectors observe HEAD requests the same as GET.
		// Size is set to bodyBytes (what GET would have written) so hooks see the
		// correct value when computing Content-Length or recording response size.
		if r, err := UnwrapResponse(w.rw); err == nil {
			r.setSize(w.bodyBytes)
			for _, fn := range r.afterFuncs {
				fn()
			}
		}
	}
}

func statusMustNotHaveBody(code int) bool {
	return (code >= 100 && code < 200) ||
		code == http.StatusNoContent ||
		code == http.StatusResetContent ||
		code == http.StatusNotModified
}

func wrapHeadHandler(handler HandlerFunc) HandlerFunc {
	return func(c *Context) error {
		originalWriter := c.Response()
		headWriter := &headResponseWriter{rw: originalWriter}

		c.SetResponse(headWriter)
		defer func() {
			c.SetResponse(originalWriter)
		}()

		err := handler(c)
		headWriter.commit()
		return err
	}
}
