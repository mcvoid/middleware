package logging

import "net/http"

type ResponseWriter struct {
	w          http.ResponseWriter
	StatusCode int
}

func NewResponseWriter(w http.ResponseWriter) *ResponseWriter {
	return &ResponseWriter{w: w}
}

func (l *ResponseWriter) Header() http.Header {
	return l.w.Header()
}

func (l *ResponseWriter) Write(b []byte) (int, error) {
	return l.w.Write(b)
}

func (l *ResponseWriter) WriteHeader(statusCode int) {
	l.StatusCode = statusCode
	l.w.WriteHeader(statusCode)
}
