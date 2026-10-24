// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2015 LabStack LLC and Echo contributors

package echo

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// ResponseHookEvent identifies a point in the response lifecycle a [ResponseHookFunc] is notified about.
type ResponseHookEvent string

const (
	// ResponseEventHeaderCommitted fires once, immediately after the status code and headers have
	// been written to the underlying transport (http.ResponseWriter.WriteHeader returned).
	ResponseEventHeaderCommitted ResponseHookEvent = "header_committed"
	// ResponseEventFirstByte fires once, after the first successful Write reaches the underlying
	// response writer. Compression middlewares report the (possibly compressed) bytes they write
	// downwards, not the handler's pre-compression bytes.
	ResponseEventFirstByte ResponseHookEvent = "first_byte"
	// ResponseEventFlush fires after every successful Flush of the underlying response writer.
	ResponseEventFlush ResponseHookEvent = "flush"
	// ResponseEventHandlerDone fires once after the handler chain (and the global error handler)
	// has returned. For responses that were never committed the reported Status is resolved the
	// same way net/http would resolve it (200 by default, status code from an error otherwise).
	ResponseEventHandlerDone ResponseHookEvent = "handler_done"
	// ResponseEventConnectionClosed fires once when the request context ends (client disconnect,
	// request cancellation) or, on a normally completed request, right after Echo finishes serving
	// it. ResponseHookInfo.Err is context.Canceled / context.DeadlineExceeded when the peer went
	// away.
	ResponseEventConnectionClosed ResponseHookEvent = "connection_closed"
)

// ResponseHookInfo is the read-only snapshot delivered to a [ResponseHookFunc].
//
// Hooks must treat the payload as ephemeral: scalar fields are copies taken at the moment the event
// occurred and do not change afterwards. Request is provided for correlation only; hooks must not
// mutate the request or the response. Hooks are invoked synchronously on the serving goroutine
// (except connection-closed events, which can originate from the context watcher goroutine), so
// they must be fast and must not panic; a panicking hook is recovered and logged but can never
// alter the status code, bytes or protocol behavior.
type ResponseHookInfo struct {
	// Event is the lifecycle point this snapshot belongs to.
	Event ResponseHookEvent
	// Time is when the event occurred.
	Time time.Time
	// Request is the in-flight request. It can be nil when a hook is attached directly to a
	// Response outside of Echo.ServeHTTP (for example in unit tests). Read-only.
	Request *http.Request
	// Status is the status code recorded by Echo at event time. It is 0 before any status was
	// chosen; ResponseEventHandlerDone always reports the resolved effective status.
	Status int
	// Size is the number of response bytes written through Echo's Response at event time.
	Size int64
	// Committed reports whether the status code/headers were already sent to the client.
	Committed bool
	// Err carries the error associated with the event, if any: the handler chain error on
	// ResponseEventHandlerDone and the context error (context.Canceled /
	// context.DeadlineExceeded) on ResponseEventConnectionClosed.
	Err error
}

// ResponseHookFunc observes a single response lifecycle event. Implementations must be read-only,
// fast and panic-free; see [ResponseHookInfo] for the exact contract.
type ResponseHookFunc func(info ResponseHookInfo)

// responseHookBus holds the per-request observer state. It is allocated only when at least one
// hook is registered, so requests without observers pay no allocations or locking. A fresh bus is
// installed on every request by Response.reset; a watcher goroutine can therefore keep holding the
// old bus after the Response has been pooled and reused without touching the new request's state.
type responseHookBus struct {
	mu sync.Mutex

	logger *slog.Logger
	req    *http.Request

	hooks []ResponseHookFunc

	// firstByte guards the exactly-once semantics of ResponseEventFirstByte.
	firstByte bool

	// watchStarted ensures the context watcher is started at most once.
	watchStarted bool

	// final/finalSet hold the last authoritative snapshot, stored before Echo finishes serving the
	// request. The close watcher uses it instead of reading Response fields, which keeps emitting
	// the close event safe even after the Response is returned to the pool.
	final    ResponseHookInfo
	finalSet bool

	// served is closed once the final snapshot is available (normal completion or panic unwind).
	served chan struct{}
}

func (b *responseHookBus) add(fn ResponseHookFunc) {
	b.mu.Lock()
	b.hooks = append(b.hooks, fn)
	b.mu.Unlock()
}

// snapshot must be called with b.mu held so that Status/Size/Committed are read consistently with
// the serving goroutine's updates.
func (b *responseHookBus) snapshot(r *Response, event ResponseHookEvent, err error) ResponseHookInfo {
	return ResponseHookInfo{
		Event:     event,
		Time:      time.Now(),
		Request:   b.req,
		Status:    r.Status,
		Size:      r.Size,
		Committed: r.Committed,
		Err:       err,
	}
}

// dispatch invokes every hook with a copy of info. Each hook is isolated: a panic is recovered and
// logged, so one misbehaving hook neither changes the response nor prevents later hooks (or later
// events) from running. Hooks are called without holding b.mu, so a slow hook never blocks
// Response field updates or deadlocks against the close watcher.
func (b *responseHookBus) dispatch(info ResponseHookInfo) {
	b.mu.Lock()
	hooks := append([]ResponseHookFunc(nil), b.hooks...)
	b.mu.Unlock()

	for _, fn := range hooks {
		b.safeCall(fn, info)
	}
}

func (b *responseHookBus) safeCall(fn ResponseHookFunc, info ResponseHookInfo) {
	defer func() {
		if recov := recover(); recov != nil {
			b.logger.Error("echo: response observer hook panicked; event delivery continues",
				"event", string(info.Event), "panic", recov)
		}
	}()
	fn(info)
}

// watchClose emits exactly one ResponseEventConnectionClosed. It exits on whichever happens
// first: the request context ending (peer disconnect / cancellation) or the request being fully
// served. When the context ends while the handler is still running, the live Response is
// snapshotted; once serving has finished the immutable final snapshot is used.
func (b *responseHookBus) watchClose(ctx context.Context, r *Response) {
	var info ResponseHookInfo
	select {
	case <-ctx.Done():
		b.mu.Lock()
		if b.finalSet {
			info = b.final
			info.Event = ResponseEventConnectionClosed
			info.Time = time.Now()
		} else {
			info = b.snapshot(r, ResponseEventConnectionClosed, ctx.Err())
		}
		b.mu.Unlock()
	case <-b.served:
		b.mu.Lock()
		info = b.final
		b.mu.Unlock()
		info.Event = ResponseEventConnectionClosed
		info.Time = time.Now()
		if ctxErr := ctx.Err(); ctxErr != nil {
			info.Err = ctxErr
		}
	}
	b.dispatch(info)
}

// AddResponseHook attaches a read-only observer to this response. Middlewares can use it to observe
// the remainder of the current request; globally registered hooks (Echo.AddResponseHook) are
// installed automatically for every request.
//
// The hook receives events for header commit, first body byte, flushes, handler completion and
// connection close. See [ResponseHookFunc] for the observer contract.
func (r *Response) AddResponseHook(fn ResponseHookFunc) {
	if fn == nil {
		return
	}
	if r.hookBus == nil {
		r.hookBus = &responseHookBus{
			logger: r.logger,
			req:    r.hookReq,
			served: make(chan struct{}),
		}
	}
	bus := r.hookBus
	bus.add(fn)

	// Hooks added during request processing (e.g. from a middleware) must still receive the
	// connection-closed event even when no global hook was registered.
	if r.reqCtx != nil {
		bus.mu.Lock()
		start := !bus.watchStarted
		bus.watchStarted = true
		ctx := r.reqCtx
		bus.mu.Unlock()
		if start {
			go bus.watchClose(ctx, r)
		}
	}
}

// initHooks is called by Echo.ServeHTTP right after Reset for every request. It remembers the
// request context (so per-request AddResponseHook can start the close watcher) and installs the
// globally registered hooks.
func (r *Response) initHooks(req *http.Request, globals []ResponseHookFunc) {
	r.reqCtx = req.Context()
	r.hookReq = req
	if len(globals) == 0 {
		return
	}
	bus := &responseHookBus{
		logger:       r.logger,
		req:          req,
		hooks:        append([]ResponseHookFunc(nil), globals...),
		watchStarted: true,
		served:       make(chan struct{}),
	}
	r.hookBus = bus
	go bus.watchClose(req.Context(), r)
}

// finishHooks emits ResponseEventHandlerDone, stores the final snapshot and releases the close
// watcher. resolvedStatus is the status net/http would emit if the response was not committed yet.
func (r *Response) finishHooks(resolvedStatus int, handlerErr error) {
	bus := r.hookBus
	if bus == nil {
		return
	}
	bus.mu.Lock()
	info := bus.snapshot(r, ResponseEventHandlerDone, handlerErr)
	if !info.Committed {
		info.Status = resolvedStatus
	}
	bus.final = info
	bus.finalSet = true
	served := bus.served
	bus.mu.Unlock()

	bus.dispatch(info)
	close(served)
}

// abortHooks is used when the handler chain panics (typically without the Recover middleware). It
// makes sure the close watcher never reads Response fields after the pooled Response is reused,
// but does not fabricate a handler-done event.
func (r *Response) abortHooks() {
	bus := r.hookBus
	if bus == nil {
		return
	}
	bus.mu.Lock()
	if !bus.finalSet {
		bus.final = bus.snapshot(r, ResponseEventConnectionClosed, context.Canceled)
		bus.finalSet = true
	}
	served := bus.served
	bus.mu.Unlock()

	select {
	case <-served:
		// Already closed by finishHooks.
	default:
		close(served)
	}
}

// setCommitted updates r.Committed under the hook bus lock so the close watcher can snapshot the
// response on a mid-request disconnect without a data race.
func (r *Response) setCommitted(committed bool) {
	if bus := r.hookBus; bus != nil {
		bus.mu.Lock()
		r.Committed = committed
		bus.mu.Unlock()
		return
	}
	r.Committed = committed
}

// setSize updates r.Size under the hook bus lock; see setCommitted.
func (r *Response) setSize(size int64) {
	if bus := r.hookBus; bus != nil {
		bus.mu.Lock()
		r.Size = size
		bus.mu.Unlock()
		return
	}
	r.Size = size
}

// emitEvent snapshots the current Response under the bus lock and dispatches the event to all
// registered hooks. It is a no-op when no observer is registered.
func (r *Response) emitEvent(event ResponseHookEvent, err error) {
	bus := r.hookBus
	if bus == nil {
		return
	}
	bus.mu.Lock()
	info := bus.snapshot(r, event, err)
	bus.mu.Unlock()
	bus.dispatch(info)
}
