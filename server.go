// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2015 LabStack LLC and Echo contributors

package echo

import (
	"cmp"
	stdContext "context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	banner = "Echo (v%s). High performance, minimalist Go web framework https://echo.labstack.com"
)

// StartConfig is for creating configured http.Server instance to start serve http(s) requests with given Echo instance
type StartConfig struct {
	// Address specifies the address where listener will start listening on to serve HTTP(s) requests
	Address string

	// HideBanner instructs Start* method not to print banner when starting the Server.
	HideBanner bool
	// HidePort instructs Start* method not to print port when starting the Server.
	HidePort bool

	// CertFilesystem is filesystem is used to read `certFile` and `keyFile` when StartTLS method is called.
	CertFilesystem fs.FS

	// TLSConfig is used to configure TLS. If Listener is set, TLSConfig is not used to create the listener.
	TLSConfig *tls.Config

	// Listener is used to start server with the custom listener.
	Listener net.Listener
	// ListenerNetwork is used configure on which Network listener will use.
	// If Listener is set, ListenerNetwork is not used.
	ListenerNetwork string
	// ListenerAddrFunc will be called after listener is created and started to listen for connections. This is useful in
	// testing situations when server is started on random port `address = ":0"` in that case you can get actual port where
	// listener is listening on.
	ListenerAddrFunc func(addr net.Addr)

	// GracefulTimeout is timeout value (defaults to 10sec) graceful shutdown will wait for server to handle ongoing requests
	// before shutting down the server.
	GracefulTimeout time.Duration
	// OnShutdownError is called when graceful shutdown results an error. for example when listeners are not shut down within
	// given timeout
	OnShutdownError func(err error)

	// BeforeServeFunc is callback that is called just before server starts to serve HTTP request.
	// Use this callback when you want to configure http.Server different timeouts/limits/etc
	BeforeServeFunc func(s *http.Server) error
}

// Start starts given Handler with HTTP(s) server.
func (sc StartConfig) Start(ctx stdContext.Context, h http.Handler) error {
	return sc.start(ctx, h)
}

// StartTLS starts given Handler with HTTPS server.
// If `certFile` or `keyFile` is `string` the values are treated as file paths.
// If `certFile` or `keyFile` is `[]byte` the values are treated as the certificate or key as-is.
func (sc StartConfig) StartTLS(ctx stdContext.Context, h http.Handler, certFile, keyFile any) error {
	certFs := sc.CertFilesystem
	if certFs == nil {
		certFs = os.DirFS(".")
	}
	cert, err := filepathOrContent(certFile, certFs)
	if err != nil {
		return err
	}
	key, err := filepathOrContent(keyFile, certFs)
	if err != nil {
		return err
	}
	cer, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return err
	}
	if sc.TLSConfig == nil {
		sc.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2"},
			//NextProtos: []string{"http/1.1"}, // Disallow "h2", allow http
		}
	}
	sc.TLSConfig.Certificates = []tls.Certificate{cer}
	return sc.start(ctx, h)
}

// start starts handler with HTTP(s) server.
func (sc StartConfig) start(ctx stdContext.Context, h http.Handler) error {
	var logger *slog.Logger
	if e, ok := h.(*Echo); ok {
		logger = e.Logger
	} else {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}

	// Connections hijacked from net/http (for example WebSocket upgrades) are invisible to
	// http.Server.Shutdown, so track them separately to release them on shutdown.
	tracker := newHijackedConnTracker()

	server := http.Server{
		Handler:  h,
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
		// defaults for GoSec rule G112 // https://github.com/securego/gosec
		// G112 (CWE-400): Potential Slowloris Attack because ReadHeaderTimeout is not configured in the http.Server
		ReadTimeout: 30 * time.Second,
		// WriteTimeout is a max time allowed to write the response
		// IMPORTANT: set this to 0 when using Server-Sent-Events (SSE) or some larger duration when serving static files
		// WriteTimeout: 30 * time.Second,

		// BaseContext is resolved once per listener and becomes the parent context of every request
		// context, so upgraded handlers can find the tracker without any per-request allocation.
		// Ordinary HTTP requests only carry an additional context value and are otherwise untouched.
		BaseContext: func(net.Listener) stdContext.Context {
			return stdContext.WithValue(stdContext.Background(), serverContextKey{}, tracker)
		},
	}

	listener := sc.Listener
	if listener == nil {
		listenerNetwork := cmp.Or(sc.ListenerNetwork, "tcp")

		ln, err := (&net.ListenConfig{}).Listen(ctx, listenerNetwork, sc.Address)
		if err != nil {
			return err
		}
		listener = ln

		if sc.TLSConfig != nil {
			listener = tls.NewListener(listener, sc.TLSConfig)
		}
	}

	if sc.ListenerAddrFunc != nil {
		sc.ListenerAddrFunc(listener.Addr())
	}

	if sc.BeforeServeFunc != nil {
		if err := sc.BeforeServeFunc(&server); err != nil {
			_ = listener.Close()
			return err
		}
	}
	if !sc.HideBanner {
		bannerText := fmt.Sprintf(banner, Version)
		logger.Info(bannerText, "version", Version)
	}
	if !sc.HidePort {
		logger.Info("http(s) server started", "address", listener.Addr().String())
	}

	wg := sync.WaitGroup{}
	defer wg.Wait() // wait for graceful shutdown goroutine to finish

	gCtx, cancel := stdContext.WithCancel(ctx) // end graceful goroutine when Serve returns early
	defer cancel()

	if sc.GracefulTimeout >= 0 {
		wg.Go(func() {
			gracefulShutdown(gCtx, &sc, &server, tracker, logger)
		})
	}

	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func filepathOrContent(fileOrContent any, certFilesystem fs.FS) (content []byte, err error) {
	switch v := fileOrContent.(type) {
	case string:
		return fs.ReadFile(certFilesystem, v)
	case []byte:
		return v, nil
	default:
		return nil, ErrInvalidCertOrKeyType
	}
}

func gracefulShutdown(shutdownCtx stdContext.Context, sc *StartConfig, server *http.Server, tracker *hijackedConnTracker, logger *slog.Logger) {
	<-shutdownCtx.Done() // wait until shutdown context is closed.
	// note: is server if closed by other means this method is still run but is good as no-op

	timeout := sc.GracefulTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	waitShutdownCtx, cancel := stdContext.WithTimeout(stdContext.Background(), timeout)
	defer cancel()

	shutdownErr := server.Shutdown(waitShutdownCtx)
	// Even when the graceful deadline for ordinary handlers expired, still release hijacked
	// connections (WebSockets): http.Server.Shutdown never tracks those, so without this they
	// would outlive Start() together with their request contexts.
	tracker.shutdownAll(waitShutdownCtx)

	if shutdownErr != nil {
		// we end up here when listeners are not shut down within given timeout
		if sc.OnShutdownError != nil {
			sc.OnShutdownError(shutdownErr)
			return
		}
		logger.Error("failed to shut down server within given timeout", "error", shutdownErr)
	}
}

// serverContextKey carries the per-server hijacked connection tracker in request contexts created
// by BaseContext.
type serverContextKey struct{}

// hijackedConnTracker keeps connections that handlers hijacked from net/http (WebSocket upgrades,
// raw TCP proxies). http.Server.Shutdown does not know about them, so the server has to close them
// itself on graceful shutdown to guarantee that the connections and their request contexts are
// released.
type hijackedConnTracker struct {
	mu     sync.Mutex
	closed bool
	// conns maps the hijacked net.Conn to a function that performs a protocol-aware graceful close
	// (e.g. sends a WebSocket GoingAway close frame) and releases the underlying connection.
	conns map[net.Conn]func()
	wg    sync.WaitGroup
}

func newHijackedConnTracker() *hijackedConnTracker {
	return &hijackedConnTracker{conns: make(map[net.Conn]func())}
}

// add registers an active hijacked connection. If shutdown already happened, the connection is
// closed immediately instead of being tracked.
func (t *hijackedConnTracker) add(conn net.Conn, gracefullyClose func()) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		gracefullyClose()
		return
	}
	t.conns[conn] = gracefullyClose
	t.wg.Add(1)
	t.mu.Unlock()
}

// remove deregisters a hijacked connection, typically from its own close path. It is a no-op when
// the connection is not tracked (for example because it was closed during shutdown).
func (t *hijackedConnTracker) remove(conn net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.conns[conn]; ok {
		delete(t.conns, conn)
		t.wg.Done()
	}
}

// shutdownAll asks every tracked connection to close gracefully and waits for their handlers to
// release them, or for ctx to expire. Closing the raw sockets unblocks in-flight reads and cancels
// the hijacked requests' contexts. It is safe to call once; subsequent calls are no-ops.
func (t *hijackedConnTracker) shutdownAll(ctx stdContext.Context) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	closers := make([]func(), 0, len(t.conns))
	for _, closeConn := range t.conns {
		closers = append(closers, closeConn)
	}
	t.mu.Unlock()

	for _, closeConn := range closers {
		closeConn()
	}

	done := make(chan struct{})
	go func() {
		t.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		// Handlers that ignore the closed socket keep the process alive no longer than any other
		// slow handler; the sockets themselves are already closed.
	}
}
