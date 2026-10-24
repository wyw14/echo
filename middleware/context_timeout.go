// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2015 LabStack LLC and Echo contributors

package middleware

import (
	"context"
	"errors"
	"time"

	"github.com/labstack/echo/v5"
)

// ContextTimeoutConfig defines the config for ContextTimeout middleware.
type ContextTimeoutConfig struct {
	// Skipper defines a function to skip middleware.
	Skipper Skipper

	// ErrorHandler is a function when error arises in middeware execution.
	ErrorHandler func(c *echo.Context, err error) error

	// Timeout configures a timeout for the middleware
	Timeout time.Duration
}

// ContextTimeout returns a middleware which returns error (503 Service Unavailable error) to client
// when underlying method returns context.DeadlineExceeded error.
func ContextTimeout(timeout time.Duration) echo.MiddlewareFunc {
	return ContextTimeoutWithConfig(ContextTimeoutConfig{Timeout: timeout})
}

// ContextTimeoutWithConfig returns a Timeout middleware with config.
func ContextTimeoutWithConfig(config ContextTimeoutConfig) echo.MiddlewareFunc {
	return toMiddlewareOrPanic(config)
}

// ToMiddleware converts Config to middleware.
func (config ContextTimeoutConfig) ToMiddleware() (echo.MiddlewareFunc, error) {
	if config.Timeout == 0 {
		return nil, errors.New("timeout must be set")
	}
	if config.Skipper == nil {
		config.Skipper = DefaultSkipper
	}
	if config.ErrorHandler == nil {
		config.ErrorHandler = func(c *echo.Context, err error) error {
			if err != nil && errors.Is(err, context.DeadlineExceeded) {
				return echo.ErrServiceUnavailable.Wrap(err)
			}
			return err
		}
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if config.Skipper(c) {
				return next(c)
			}

			// A WebSocket upgrade hijacks the connection and the session can legitimately outlive
			// any request timeout: canceling its context mid-session would tear down a healthy
			// socket (for example an idle stream waiting for the next frame). The upgraded
			// connection owns its own context lifecycle instead, which is released when the socket
			// closes, when the peer half-closes it or when the server shuts down.
			// Handshake failures are handled as ordinary HTTP errors and release normally.
			if c.IsWebSocket() {
				return next(c)
			}

			timeoutContext, cancel := context.WithTimeout(c.Request().Context(), config.Timeout)
			defer cancel()

			c.SetRequest(c.Request().WithContext(timeoutContext))

			if err := next(c); err != nil {
				return config.ErrorHandler(c, err)
			}
			return nil
		}
	}, nil
}
