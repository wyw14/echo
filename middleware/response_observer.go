// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2015 LabStack LLC and Echo contributors

package middleware

import (
	"errors"

	"github.com/labstack/echo/v5"
)

// ResponseObserverConfig is configuration for the ResponseObserver middleware.
type ResponseObserverConfig struct {
	// Skipper defines a function to skip middleware.
	Skipper Skipper

	// OnEvent is called once per response lifecycle event of the current request: header commit,
	// first body byte, each flush, handler completion and connection close (including peer
	// disconnects). The callback is read-only: it must not modify the request or the response and
	// it must be fast and panic-free — a panicking observer is recovered and logged by Echo and
	// can never change the response status code, streaming behavior or HTTP/2 semantics.
	//
	// Example wiring events to the structured (slog) logger:
	//
	//	e.Use(middleware.ResponseObserverWithConfig(middleware.ResponseObserverConfig{
	//		OnEvent: func(c *echo.Context, ev echo.ResponseHookInfo) {
	//			c.Logger().Debug("response event",
	//				"event", string(ev.Event),
	//				"status", ev.Status,
	//				"size", ev.Size,
	//			)
	//		},
	//	}))
	OnEvent func(c *echo.Context, event echo.ResponseHookInfo)
}

// ResponseObserver returns a middleware which forwards response lifecycle events of every request
// to the given callback.
func ResponseObserver(onEvent func(c *echo.Context, event echo.ResponseHookInfo)) echo.MiddlewareFunc {
	return ResponseObserverWithConfig(ResponseObserverConfig{OnEvent: onEvent})
}

// ResponseObserverWithConfig returns a ResponseObserver middleware with config.
func ResponseObserverWithConfig(config ResponseObserverConfig) echo.MiddlewareFunc {
	mw, err := config.ToMiddleware()
	if err != nil {
		panic(err)
	}
	return mw
}

// ToMiddleware converts ResponseObserverConfig into middleware or returns an error for invalid
// configuration.
func (config ResponseObserverConfig) ToMiddleware() (echo.MiddlewareFunc, error) {
	if config.Skipper == nil {
		config.Skipper = DefaultSkipper
	}
	if config.OnEvent == nil {
		return nil, errors.New("missing OnEvent callback for response observer middleware")
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if config.Skipper(c) {
				return next(c)
			}

			// Attach to the underlying *echo.Response so events keep arriving even when later
			// middlewares (gzip, proxy, ...) wrap c.Response() with their own writers.
			if r, err := echo.UnwrapResponse(c.Response()); err == nil {
				r.AddResponseHook(func(event echo.ResponseHookInfo) {
					config.OnEvent(c, event)
				})
			}
			return next(c)
		}
	}, nil
}
