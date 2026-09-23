package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func serve(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	old := baseURL
	baseURL = func(string) string { return srv.URL }
	t.Cleanup(func() { baseURL = old })
}

func TestFetch(t *testing.T) {
	serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("# comment\nContact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00Z\n"))
	})
	f, err := fetch(context.Background(), "example.com")
	if err != nil || f.fields["contact"] != "mailto:security@example.com" || f.fields["expires"] != "2030-01-01T00:00:00Z" {
		t.Fatalf("fetch = %+v, %v", f, err)
	}
}

func TestFetchProblems(t *testing.T) {
	for _, tt := range []struct {
		status      int
		contentType string
		problem     string
		err         bool
	}{
		{http.StatusNotFound, "text/plain", "404 Not Found", false},
		{http.StatusOK, "text/html", `with Content-Type "text/html"`, false},
		{http.StatusInternalServerError, "text/plain", "", true},
	} {
		serve(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", tt.contentType)
			w.WriteHeader(tt.status)
		})
		f, err := fetch(context.Background(), "example.com")
		if tt.err != (err != nil) || !tt.err && (f.fields != nil || !strings.Contains(f.problem, tt.problem)) {
			t.Errorf("%d %s: %+v, %v", tt.status, tt.contentType, f, err)
		}
	}
}

func TestExpiry(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for expires, want := range map[string]string{
		"":                     "has no Expires field",
		"next year":            "invalid Expires field",
		"2026-08-01T00:00:00Z": "",
		"2026-09-10T00:00:00Z": "expires soon",
		"2027-06-01T00:00:00Z": "none",
		"2027-06-01t00:00:00z": "none",
	} {
		f := &file{url: "u", fields: map[string]string{"expires": expires}}
		got := expiry(f, now, 30)
		switch {
		case want == "none" && got != nil,
			want != "none" && (len(got) != 1 || !strings.Contains(got[0].Title, want)):
			t.Errorf("%q: %+v, want %q", expires, got, want)
		}
	}
}
