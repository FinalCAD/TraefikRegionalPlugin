package TraefikRegionalPlugin_test

import (
	"context"
	"github.com/finalcad/TraefikRegionalPlugin"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRedirectToEuropeFromUuid(t *testing.T) {
	cfg := TraefikRegionalPlugin.CreateConfig()
	cfg.GlobalHostUrls = []string{"api.massive-dynamic.com", "api.development.massive-dynamic.com"}
	cfg.MatchPaths = []TraefikRegionalPlugin.MatchPathRegexConfig{
		{
			Regex: "^\\/project\\/(([0-9A-Fa-f]{8}[-]){2,}([0-9A-Fa-f]{4}[-]){3}[0-9A-Fa-f]{12})$",
			Index: 0,
			Type:  "PATH",
		},
	}
	cfg.DestinationHosts = []TraefikRegionalPlugin.DestinationHostConfig{
		{
			Host:  "api.ja.massive-dynamic.com",
			Value: 1,
		},
		{
			Host:  "api.na.massive-dynamic.com",
			Value: 2,
		},
	}
	cfg.IsLittleEndian = true

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := TraefikRegionalPlugin.New(ctx, next, cfg, "regional-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://api.massive-dynamic.com/project/31e6aeb6-1411f3f2-3d9b-46fd-9d52-dd91585b6a8e?test=toto&toto=test", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	assertResponseCode(t, recorder, http.StatusFound)
	assertResponseHeader(t, recorder, "Location", "http://api.ja.massive-dynamic.com/project/31e6aeb6-1411f3f2-3d9b-46fd-9d52-dd91585b6a8e?test=toto&toto=test")
}

func TestRedirectToEuropeFromJwt(t *testing.T) {
	cfg := TraefikRegionalPlugin.CreateConfig()
	cfg.GlobalHostUrls = []string{"api.massive-dynamic.com", "api.development.massive-dynamic.com"}
	cfg.MatchPaths = []TraefikRegionalPlugin.MatchPathRegexConfig{
		{
			Regex:   "^\\/project$",
			Type:    "JWT",
			Methods: []string{"POST"},
		},
	}
	cfg.DestinationHosts = []TraefikRegionalPlugin.DestinationHostConfig{
		{
			Host:  "api.ja.massive-dynamic.com",
			Value: 1,
		},
		{
			Host:  "api.na.massive-dynamic.com",
			Value: 2,
		},
	}
	cfg.IsLittleEndian = true

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := TraefikRegionalPlugin.New(ctx, next, cfg, "regional-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://api.massive-dynamic.com/project", nil)
	req.Header.Set("Authorization", "Bearer eyJraWQiOiJuWERkQnZUSko5MjgyTG1adGo5MWk3aDcxSXZhXzdlVzhGYmJEOFZ4MmxVIiwiYWxnIjoiUlMyNTYifQ.eyJ2ZXIiOjEsImp0aSI6IkFULlU0NnpwcDQxdmd2Y2l6YUhIQ1A2MlZxcEFXb1RGMWdlOVd6WTFrWHJNMlEiLCJpc3MiOiJodHRwczovL3ByZXZpZXcuZmluYWxjYWQuY29tL29hdXRoMi9hdXN2MDU2dDlBS0htU1V2azB4NiIsImF1ZCI6ImFwaTovL2RlZmF1bHQiLCJpYXQiOjE2MTY1MTMxMTcsImV4cCI6MTYxNjU5OTUxNywiY2lkIjoiMG9hc2tsYW5pUDlNZVU5ZnMweDYiLCJ1aWQiOiIwMHV0ZGpxbTNIVE5UU05FRjB4NiIsInNjcCI6WyJwcm9maWxlIiwib3BlbmlkIl0sInN1YiI6Im1heGltZS5jaGFybGVzQGZpbmFsY2FkLmNvbSIsImZjVXNlcklkIjoiYjhjZTA5MjgtNWUxM2E5NjUtMGUwNC00NDQ5LTg0MDQtMWRjMzIxN2NlYjY5In0.JBO8rJPxPUwj4rFzpsgCAAAUOqGcwqyapInN6rKayDNkHShgLyPxGPsx0eAp6Y0s2-80k9Tff3TBIKR6S9jFmmhogXN2PWMoCYGNJSJScNPzQC4ReIGifIIMJd-wEjQ8hB4wB--dZIhomZ6f9pE4L0G0aG6O8qY1BlGfs3N_O684JqzQucb2e1sl_pscsLeSW90zcorX6FakbFmRthAMmmfngTnT70q9QKIOHJ3DL1lxfgLj-KFA5XSRDi9mCsURqAe1bwhcDw3eeoMRWY91mGDi7bVeLLhVn5iGHoWkhDErn0wrtxMVfQLpYqhAE77KD83QcCPvqHooREQ60cRXqg")
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	assertResponseCode(t, recorder, http.StatusTemporaryRedirect)
	assertResponseHeader(t, recorder, "Location", "http://api.ja.massive-dynamic.com/project")
}

func TestNoRedirectOnDefault(t *testing.T) {
	cfg := TraefikRegionalPlugin.CreateConfig()
	cfg.GlobalHostUrls = []string{"api.massive-dynamic.com", "api.development.massive-dynamic.com"}
	cfg.MatchPaths = []TraefikRegionalPlugin.MatchPathRegexConfig{
		{
			Regex: "^\\/project\\/(([0-9A-Fa-f]{8}[-]){2,}([0-9A-Fa-f]{4}[-]){3}[0-9A-Fa-f]{12})$",
			Index: 0,
		},
	}
	cfg.DestinationHosts = []TraefikRegionalPlugin.DestinationHostConfig{
		{
			Host:      "api.ja.massive-dynamic.com",
			Value:     1,
			IsCurrent: true,
		},
		{
			Host:  "api.na.massive-dynamic.com",
			Value: 2,
		},
	}
	cfg.IsLittleEndian = true

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := TraefikRegionalPlugin.New(ctx, next, cfg, "demo-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://api.massive-dynamic.com/project/31e6aeb6-1411f3f2-3d9b-46fd-9d52-dd91585b6a8e", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	assertResponseCode(t, recorder, http.StatusOK)
	assertUrl(t, req, "api.massive-dynamic.com")
}

func assertResponseCode(t *testing.T, recorder *httptest.ResponseRecorder, statusCode int) {
	t.Helper()

	if recorder.Code != statusCode {
		t.Errorf("Invalid status code. Expected=%d Current=%d", statusCode, recorder.Code)
	}
}

func assertResponseHeader(t *testing.T, recorder *httptest.ResponseRecorder, key string, value string) {
	t.Helper()

	if recorder.Header().Get(key) != value {
		t.Errorf("invalid header value: %s", recorder.Header().Get(key))
	}
}

func assertUrl(t *testing.T, req *http.Request, expected string) {
	t.Helper()

	if req.Host != expected || req.URL.Host != expected {
		t.Errorf("invalid host")
	}
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("invalid header value: %s", req.Header.Get(key))
	}
}
