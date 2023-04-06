package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"runtime/debug"
	"time"

	"github.com/mcvoid/middleware/internal/logging"
	"github.com/mcvoid/middleware/internal/rate"
)

const (
	headerContentType = "Content-Type"
	headerAccept      = "Accept"
	jsonMimeType      = "application/json"
)

type ctxKey string

const (
	keynamespace ctxKey = "github.com/mcvoid/middleware/"
	jsonCtxKey   ctxKey = keynamespace + "json"
	rawCtxKey    ctxKey = keynamespace + "raw"
	textCtxKey   ctxKey = keynamespace + "text"
)

type BodyGetter[T any] func(r *http.Request) (val T, ok bool)

// Parses the JSON in the request body, retrievable through the returned getBody function.
// Requires a Content-Type of 'application/json', returns 400 if unable to parse the contents.
func JSON[T any](getBody *BodyGetter[T]) Middleware {
	// get a unique name for this type so that
	// it is in a key unique from other types
	var val T
	typeName := reflect.TypeOf(val).Name()
	key := jsonCtxKey + "[" + ctxKey(typeName) + "]"

	*getBody = func(r *http.Request) (val T, ok bool) {
		ctxVal := r.Context().Value(key)
		if ctxVal == nil {
			return val, false
		}
		val, ok = ctxVal.(T)
		return val, ok
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			contentType := r.Header.Get(headerContentType)
			if contentType != jsonMimeType {
				w.Header().Add(headerAccept, jsonMimeType)
				http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
				return
			}

			var val T
			err := json.NewDecoder(r.Body).Decode(&val)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, key, val)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

// Reads the request body into a byte slice, retrievable through the returned getBody function.
func Raw(getBody *BodyGetter[[]byte]) Middleware {
	*getBody = func(r *http.Request) (val []byte, ok bool) {
		ctxVal := r.Context().Value(rawCtxKey)
		if ctxVal == nil {
			return val, false
		}
		val, ok = ctxVal.([]byte)
		return val, ok
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, rawCtxKey, body)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

// Reads the request body into a string, retrievable through the returned getBody function.
func Text(getBody *BodyGetter[string]) Middleware {
	*getBody = func(r *http.Request) (val string, ok bool) {
		ctxVal := r.Context().Value(textCtxKey)
		if ctxVal == nil {
			return val, false
		}
		val, ok = ctxVal.(string)
		return val, ok
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, textCtxKey, body)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

// Filters the request such that it only allows through requests which provide
// Basic authentication along with the correct user name and password. Returns a
// 401 status code otherwise.
func BasicAuth(user, pw string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			givenUser, givenPw, ok := r.BasicAuth()
			if !ok || givenUser != user || givenPw != pw {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Presents stdlib's http.TimeoutHandler as a chainable middleware.
// Runs with a given time limit. Returns with a 503 if the handler takes
// longer than the given limit.
func Timeout(duration time.Duration, msg string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.TimeoutHandler(next, duration, msg)
	}
}

// Presents stdlib's http.StripPrefix as a chainable middleware.
// Removes the given prefix from the URL's path.
func StripPrefix(prefix string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.StripPrefix(prefix, next)
	}
}

// Presents stdlib's http.MaxBytesHandler as a chainable middleware.
// Wraps the ResponseWriter and RequestBody in a MaxBytesReader.
func MaxBytes(n int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.MaxBytesHandler(next, n)
	}
}

// Rate-limits incoming requests per handler. If too many requests occur per second,
// responds with a 429 status.
// To rate limit the entire server wrap the entire router or ServeMux in RateLimit.
//
// Wraps golang.org/x/time/rate.Limiter as middleware, but copies it to an internal
// package to avoid a dependency.
//
// limitInRequestsPerSecond is the rate at which requests are processed.
// burst is the buffer queue size which can hold requests waiting to be processed.
func RateLimit(limitInRequestsPerSecond float64, burst int) Middleware {
	return func(next http.Handler) http.Handler {
		lim := rate.NewLimiter(rate.Limit(limitInRequestsPerSecond), burst)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if lim.Allow() {
				next.ServeHTTP(w, r)
				return
			}

			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		})
	}
}

// Mesures how long a request takes and reports the start and end times
// to the given callback function.
func Timer(cb func(start, end time.Time)) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			end := time.Now()
			cb(start, end)
		})
	}
}

type Logger interface {
	Printf(format string, v ...any)
}

// Logs information about requests.
// Meant to be used with a logger with the same interface as stdlib's log.Logger
func Log(logger Logger, format string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			now := time.Now()
			wrappedRW := logging.NewResponseWriter(w)
			next.ServeHTTP(wrappedRW, r)
			logger.Printf(logging.Format(format, logging.FormatOptions{
				"s": fmt.Sprintf("%d: %s", wrappedRW.StatusCode, http.StatusText(wrappedRW.StatusCode)),
				"m": r.Method,
				"h": r.Host,
				"p": r.Proto,
				"r": r.Referer(),
				"l": fmt.Sprintf("%d", r.ContentLength),
				"a": r.RemoteAddr,
				"u": r.RequestURI,
				"t": now.String(),
				"x": string(debug.Stack()),
			}))
		})
	}
}

// Logs information if a handler panics.
// Meant to be used with a logger with the same interface as stdlib's log.Logger
func LogOnPanic(logger Logger, format string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			now := time.Now()
			wrappedRW := logging.NewResponseWriter(w)
			next.ServeHTTP(wrappedRW, r)

			if err := recover(); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				logger.Printf(logging.Format(format, logging.FormatOptions{
					"s": fmt.Sprintf("%d: %s", wrappedRW.StatusCode, http.StatusText(wrappedRW.StatusCode)),
					"m": r.Method,
					"h": r.Host,
					"p": r.Proto,
					"r": r.Referer(),
					"l": fmt.Sprintf("%d", r.ContentLength),
					"a": r.RemoteAddr,
					"u": r.RequestURI,
					"t": now.String(),
					"x": string(debug.Stack()),
				}))
			}
		})
	}
}

type Slogger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
}

// Logs information about requests to a structured logger
// Meant to be used with golang.org/x/exp/slog.Logger
func Slog(logger Slogger, msg string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			now := time.Now()
			wrappedRW := logging.NewResponseWriter(w)
			next.ServeHTTP(wrappedRW, r)
			logger.Info(
				msg,
				"statusCode",
				fmt.Sprintf("%d: %s", wrappedRW.StatusCode, http.StatusText(wrappedRW.StatusCode)),
				"method", r.Method,
				"host", r.Host,
				"pproto", r.Proto,
				"referer", r.Referer(),
				"length", fmt.Sprintf("%d", r.ContentLength),
				"addr", r.RemoteAddr,
				"uri", r.RequestURI,
				"time", now.String(),
				"stack", string(debug.Stack()),
			)
		})
	}
}

// Logs information about requests to a structured logger
func SlogOnPanic(logger Slogger, msg string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			now := time.Now()
			wrappedRW := logging.NewResponseWriter(w)
			next.ServeHTTP(wrappedRW, r)

			if err := recover(); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				next.ServeHTTP(wrappedRW, r)
				logger.Error(
					msg,
					"statusCode",
					fmt.Sprintf("%d: %s", wrappedRW.StatusCode, http.StatusText(wrappedRW.StatusCode)),
					"method", r.Method,
					"host", r.Host,
					"pproto", r.Proto,
					"referer", r.Referer(),
					"length", fmt.Sprintf("%d", r.ContentLength),
					"addr", r.RemoteAddr,
					"uri", r.RequestURI,
					"time", now.String(),
					"stack", string(debug.Stack()),
				)
			}
		})
	}
}

// calls a lifecycle hook with request/response state before running the handler
func BeforeHandler(hook func(w http.ResponseWriter, r *http.Request)) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hook(w, r)
			next.ServeHTTP(w, r)
		})
	}
}

// calls a lifecycle hook with request/response state after running the handler
func AfterHandler(hook func(w http.ResponseWriter, r *http.Request)) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			hook(w, r)
		})
	}
}
