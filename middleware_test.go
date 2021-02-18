package TraefikRegionalPlugin_test

import (
	"context"
	"github.com/finalcad/TraefikRegionalPlugin"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRedirectToEurope(t *testing.T) {
	cfg := TraefikRegionalPlugin.CreateConfig()
	cfg.GlobalHostUrls = []string{"api.massive-dynamic.com", "api.development.massive-dynamic.com"}
	cfg.MatchPaths = []TraefikRegionalPlugin.MatchPathRegexConfig{
		{
			Regex: "^\\/project\\/(([0-9A-Fa-f]{8}[-]){2,}([0-9A-Fa-f]{4}[-]){3}[0-9A-Fa-f]{12})$",
			Index: 0,
		},
	}
	cfg.DestinationHosts = []TraefikRegionalPlugin.DestinationHostConfig {
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://api.massive-dynamic.com/project/31e6aeb6-1411f3f2-3d9b-46fd-9d52-dd91585b6a8e", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	assertResponseCode(t, recorder, http.StatusTemporaryRedirect)
	assertResponseHeader(t, recorder, "Location", "http://api.ja.massive-dynamic.com/project/31e6aeb6-1411f3f2-3d9b-46fd-9d52-dd91585b6a8e")
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
	cfg.DestinationHosts = []TraefikRegionalPlugin.DestinationHostConfig {
		{
			Host:  "api.ja.massive-dynamic.com",
			Value: 1,
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
