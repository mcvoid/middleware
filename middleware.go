package middleware

import "net/http"

type Middleware func(next http.Handler) http.Handler

// A middleware chain which can be applied to a handler.
type Builder struct {
	mw []Middleware
}

// Creates a chain of middleware to apply to a handler.
func New(mw ...Middleware) *Builder {
	return &Builder{mw}
}

// Apply the middleware chain to a handler.
func (b *Builder) Then(h http.Handler) http.Handler {
	wrapped := h

	mw := b.mw
	for len(mw) > 0 {
		next := wrapped
		thisMw := mw[len(mw)-1]
		mw = mw[:len(mw)-1]
		wrapped = thisMw(next)
	}

	return wrapped
}

// Make a new chain out of an existing one with additional middleware at the end.
func (b *Builder) Append(mw ...Middleware) *Builder {
	return &Builder{append(b.mw, mw...)}
}
