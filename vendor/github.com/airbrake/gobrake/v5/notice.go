package gobrake

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/pkg/errors"
)

var defaultContextOnce sync.Once
var defaultContext map[string]interface{}

func getDefaultContext() map[string]interface{} {
	defaultContextOnce.Do(func() {
		defaultContext = map[string]interface{}{
			"notifier": map[string]interface{}{
				"name":    notifierName,
				"version": notifierVersion,
				"url":     "https://github.com/airbrake/gobrake",
			},

			"language":     runtime.Version(),
			"os":           runtime.GOOS,
			"architecture": runtime.GOARCH,
		}

		if s, err := os.Hostname(); err == nil {
			defaultContext["hostname"] = s
		}

		if wd, err := os.Getwd(); err == nil {
			defaultContext["rootDirectory"] = wd
		}

		if s := gopath(); s != "" {
			defaultContext["gopath"] = s
		}
	})
	return defaultContext
}

func gopath() string {
	path := os.Getenv("GOPATH")
	if path != "" {
		return path
	}

	path, ok := os.LookupEnv("HOME")
	if ok {
		return filepath.Join(path, "go")
	}

	return ""
}

type Error struct {
	Type      string       `json:"type"`
	Message   string       `json:"message"`
	Backtrace []StackFrame `json:"backtrace"`
}

type StackFrame struct {
	File string         `json:"file"`
	Line int            `json:"line"`
	Func string         `json:"function"`
	Code map[int]string `json:"code,omitempty"`
}

type Notice struct {
	Id    string `json:"-"` // id returned by SendNotice
	Error error  `json:"-"` // error returned by SendNotice

	Errors  []Error                `json:"errors"`
	Context map[string]interface{} `json:"context"`
	Env     map[string]interface{} `json:"environment"`
	Session map[string]interface{} `json:"session"`
	Params  map[string]interface{} `json:"params"`
}

func (n *Notice) String() string {
	if len(n.Errors) == 0 {
		return "Notice<no errors>"
	}
	e := n.Errors[0]
	return fmt.Sprintf("Notice<%s: %s>", e.Type, e.Message)
}

func (n *Notice) SetRequest(req *http.Request) {
	n.Context["url"] = req.URL.String()
	n.Context["httpMethod"] = req.Method
	if ua := req.Header.Get("User-Agent"); ua != "" {
		n.Context["userAgent"] = ua
	}
	n.Context["userAddr"] = remoteAddr(req)

	for k, v := range req.Header {
		if len(v) == 1 {
			n.Env[k] = v[0]
		} else {
			n.Env[k] = v
		}
	}
}

func remoteAddr(req *http.Request) string {
	if s := req.Header.Get("X-Forwarded-For"); s != "" {
		parts := strings.Split(s, ",")
		return parts[0]
	}

	if s := req.Header.Get("X-Real-Ip"); s != "" {
		return s
	}

	parts := strings.Split(req.RemoteAddr, ":")
	return parts[0]
}

func NewNotice(e interface{}, req *http.Request, depth int) *Notice {
	notice, ok := e.(*Notice)
	if ok {
		return notice
	}

	typeName := getTypeName(e)
	notice = &Notice{
		Errors: []Error{{
			Type:    typeName,
			Message: fmt.Sprint(e),
		}},
		Context: make(map[string]interface{}),
		Env:     make(map[string]interface{}),
		Session: make(map[string]interface{}),
		Params:  make(map[string]interface{}),
	}

	for k, v := range getDefaultContext() {
		notice.Context[k] = v
	}

	if depth != -1 {
		packageName, backtrace := getBacktrace(e, depth+2)
		notice.Errors[0].Backtrace = backtrace
		notice.Context["component"] = packageName
	}

	if req != nil {
		notice.SetRequest(req)
	}

	return notice
}

// getTypeName returns the type name of e.
func getTypeName(e interface{}) string {
	if err, ok := e.(error); ok {
		e = errors.Cause(err)
	}
	return fmt.Sprintf("%T", e)
}
