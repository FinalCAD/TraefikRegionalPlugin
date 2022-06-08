package TraefikRegionalPlugin

import (
	"context"
	"errors"
	"fmt"
	"github.com/FinalCAD/TraefikRegionalPlugin/jwt"
	"github.com/FinalCAD/TraefikRegionalPlugin/regional_uuid"
	"io"
	"net/http"
	"net/url"
	"regexp"
)

const (
	MatchPathTypePath       = "PATH"
	MatchPathTypeJwt        = "JWT"
	JwtClaimUserId          = "fcUserId"
	RoutingMethodRedirect   = "Redirect"
	RoutingMethodDirectCall = "DirectCall"
)

type MatchPathRegexConfig struct {
	Regex   string   `json:"regex,omitempty"`
	Type    string   `json:"type,omitempty"`
	Index   int      `json:"index,omitempty"`
	Methods []string `json:"methods,omitempty"`
}
type DestinationHostConfig struct {
	Host      string `json:"host,omitempty"`
	Value     int    `json:"value,omitempty"`
	IsCurrent bool   `json:"is_current,omitempty"`
}

type Config struct {
	GlobalHostUrls   []string                `json:"global_host_urls,omitempty"`
	MatchPaths       []MatchPathRegexConfig  `json:"match_urls,omitempty"`
	DestinationHosts []DestinationHostConfig `json:"destination_hosts,omitempty"`
	IsLittleEndian   bool                    `json:"little_endian,omitempty"`
	DefaultScheme    string                  `json:"default_schema,omitempty"`
	Log              string                  `json:"log,omitempty"`
	RoutingMethod    string                  `json:"routing_method,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		GlobalHostUrls:   make([]string, 0),
		MatchPaths:       make([]MatchPathRegexConfig, 0),
		DestinationHosts: make([]DestinationHostConfig, 0),
		IsLittleEndian:   true,
		DefaultScheme:    "https",
		Log:              Information,
		RoutingMethod:    RoutingMethodRedirect,
	}
}

type matchPathRegex struct {
	stringRegex string
	regex       *regexp.Regexp
	matchType   string
	index       int
	methods     []string
}
type destinationHost struct {
	host      string
	value     int
	isCurrent bool
}

type RegionalRouter struct {
	next             http.Handler
	globalHostUrls   []string
	matchPaths       []matchPathRegex
	destinationHosts []destinationHost
	defaultScheme    string
	isLittleEndian   bool
	name             string
	routingMethod    string
}

type redirectionInfo struct {
	scheme        string
	host          string
	path          string
	routingMethod string
	rawQuery      string
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	var matchPathRegexp []matchPathRegex

	Log.SetLevel(config.Log)

	Log.LogInformation("Load configuration")

	Log.LogDebug(fmt.Sprintf("%d GlobalHosts found", len(config.GlobalHostUrls)))
	for i := 0; i < len(config.GlobalHostUrls); i++ {
		Log.LogDebug(fmt.Sprintf("\tGlobalHost: %s", config.GlobalHostUrls[i]))
	}

	Log.LogDebug(fmt.Sprintf("%d MatchPaths found", len(config.MatchPaths)))
	for i := 0; i < len(config.MatchPaths); i++ {
		regex, err := regexp.Compile(config.MatchPaths[i].Regex)
		if err != nil {
			Log.LogError(fmt.Sprintf("Invalid regex `%s`", config.MatchPaths[i].Regex))
			return nil, errors.New("invalid regexp `" + config.MatchPaths[i].Regex + "`")
		}
		matchPathRegex := matchPathRegex{
			regex:       regex,
			index:       config.MatchPaths[i].Index,
			stringRegex: config.MatchPaths[i].Regex,
			methods:     config.MatchPaths[i].Methods,
			matchType:   config.MatchPaths[i].Type,
		}
		if config.MatchPaths[i].Type == MatchPathTypeJwt {
			Log.LogDebug(fmt.Sprintf("\tMatchPath JWT: Regex=%s", config.MatchPaths[i].Regex))
		} else if config.MatchPaths[i].Type == MatchPathTypePath {
			Log.LogDebug(fmt.Sprintf("\tMatchPath PATH: Regex=%s Index=%d", config.MatchPaths[i].Regex, config.MatchPaths[i].Index))
		} else {
			Log.LogWarning(fmt.Sprintf("\tUnknown type %s. The regex %s is set to %s", config.MatchPaths[i].Type, config.MatchPaths[i].Regex, MatchPathTypePath))
			matchPathRegex.matchType = MatchPathTypePath
		}
		matchPathRegexp = append(matchPathRegexp, matchPathRegex)
	}

	Log.LogDebug(fmt.Sprintf("%d Destination hosts found", len(config.DestinationHosts)))
	var destinationHosts []destinationHost
	for i := 0; i < len(config.DestinationHosts); i++ {
		Log.LogDebug(fmt.Sprintf("Destination host: Host=%s Region=%d IsCurrent=%t", config.DestinationHosts[i].Host, config.DestinationHosts[i].Value, config.DestinationHosts[i].IsCurrent))
		destinationHosts = append(destinationHosts, destinationHost{
			host:      config.DestinationHosts[i].Host,
			value:     config.DestinationHosts[i].Value,
			isCurrent: config.DestinationHosts[i].IsCurrent,
		})
	}
	if config.IsLittleEndian {
		Log.LogDebug("Endianness=little")
	} else {
		Log.LogDebug("Endianness=big")
	}

	routingMethod := RoutingMethodRedirect
	if config.RoutingMethod == RoutingMethodDirectCall {
		routingMethod = RoutingMethodDirectCall
	}
	Log.LogDebug(fmt.Sprintf("RoutingMethod configured to %s", routingMethod))

	return &RegionalRouter{
		globalHostUrls:   config.GlobalHostUrls,
		matchPaths:       matchPathRegexp,
		destinationHosts: destinationHosts,
		isLittleEndian:   config.IsLittleEndian,
		defaultScheme:    config.DefaultScheme,
		next:             next,
		name:             name,
		routingMethod:    routingMethod,
	}, nil
}

func isGlobalHost(url string, globalHostUrls []string) bool {
	for i := 0; i < len(globalHostUrls); i++ {
		if globalHostUrls[i] == url {
			return true
		}
	}
	return false
}

func findRegionHost(region byte, hosts []destinationHost, previousHost string) (string, error) {
	for i := 0; i < len(hosts); i++ {
		if int(region) == hosts[i].value {
			if hosts[i].isCurrent {
				Log.LogDebug("Redirect on current host. Send previous host")
				return previousHost, nil
			}
			return hosts[i].host, nil
		}
	}
	return "", errors.New("no region found")
}

func isMatching(matchPath *matchPathRegex, req *http.Request) bool {
	Log.LogDebug(fmt.Sprintf("Try regex: %s on path: %s with result: %t", matchPath.stringRegex, req.URL.Path, matchPath.regex.MatchString(req.URL.Path)))
	if matchPath.regex.MatchString(req.URL.Path) {
		if matchPath.methods != nil && len(matchPath.methods) > 0 {
			Log.LogDebug(fmt.Sprintf("Filter by methods"))
			for _, value := range matchPath.methods {
				if value == req.Method {
					Log.LogInformation(fmt.Sprintf("The current Path `%s` `%s` match with url rewrite rules", req.Method, req.URL.Path))
					return true
				}
			}
		} else {
			Log.LogInformation(fmt.Sprintf("The current Path `%s` match with url rewrite rules", req.URL.Path))
			return true
		}
	}
	return false
}

func redirectFromUuid(region byte,
	req *http.Request,
	regionalRouter *RegionalRouter) (*redirectionInfo, error) {
	regionHost, err := findRegionHost(region, regionalRouter.destinationHosts, req.Host)
	if err != nil {
		Log.LogError(fmt.Sprintf("Can't find valid region"))
		return nil, err
	}
	if regionHost != req.Host {
		newLocation := &redirectionInfo{
			host:          regionHost,
			path:          req.URL.Path,
			scheme:        "http",
			routingMethod: regionalRouter.routingMethod,
			rawQuery:      req.URL.RawQuery,
		}

		if req.TLS != nil {
			newLocation.scheme = "https"
		}

		Log.LogInformation(fmt.Sprintf("Redirection to location: %s://%s%s", newLocation.scheme, newLocation.host, newLocation.path))
		return newLocation, nil
	} else {
		Log.LogDebug(fmt.Sprintf("Same host. No redirection. RequestHost=%s RedirectHost=%s", req.Host, regionHost))
		return nil, nil
	}
}

func handlePathRedirection(matchPath *matchPathRegex,
	req *http.Request,
	regionalRouter *RegionalRouter) (*redirectionInfo, error) {
	subMatch := matchPath.regex.FindStringSubmatch(req.URL.Path)
	if len(subMatch) >= matchPath.index+1 {
		rUuid, err := regional_uuid.Regional.Read(subMatch[matchPath.index+1], regionalRouter.isLittleEndian)
		if err != nil {
			Log.LogError(fmt.Sprintf("Fail to parse ExUuid %s", subMatch[matchPath.index+1]))
			return nil, err
		}
		newLocation, err := redirectFromUuid(rUuid.Region, req, regionalRouter)
		if err != nil {
			return nil, err
		}
		if newLocation != nil {
			return newLocation, nil
		}
	}
	return nil, nil
}

func handleJwtRedirection(req *http.Request,
	regionalRouter *RegionalRouter) (*redirectionInfo, error) {
	authorizationToken := req.Header.Get("Authorization")
	if authorizationToken == "" {
		return nil, nil
	}
	token, err := jwt.Parse(authorizationToken)
	if err != nil {
		return nil, err
	}
	if token != nil {
		value, contain := token.Payload[JwtClaimUserId]
		if contain {
			Log.LogDebug(fmt.Sprintf("Token found with userId=%s", value))
			rUuid, err := regional_uuid.Regional.Read(value, regionalRouter.isLittleEndian)
			if err != nil {
				return nil, err
			}
			newLocation, err := redirectFromUuid(rUuid.Region, req, regionalRouter)
			if err != nil {
				return nil, err
			}
			if newLocation != nil {
				return newLocation, nil
			}
		}
	}
	return nil, nil
}

func proxyHTTPRequest(rw http.ResponseWriter, req *http.Request, destination string) {
	parsedURL, err := url.Parse(destination)
	if err != nil {
		Log.LogError(fmt.Sprintf("%v", err))
		rw.WriteHeader(http.StatusBadGateway)
		// TODO log into airbrake when airbrake is supported
		return
	}
	Log.LogInformation(fmt.Sprintf("Incoming request: %s %s %s", req.Proto, req.Method, req.URL.String()))
	reqClone := req.Clone(context.TODO())
	reqClone.URL = parsedURL
	reqClone.Host = parsedURL.Host
	reqClone.RequestURI = ""
	Log.LogInformation(fmt.Sprintf("Outcoming request:  %s %s %s", reqClone.Proto, reqClone.Method, reqClone.URL.String()))
	httpClient := http.Client{}
	resp, err := httpClient.Do(reqClone)
	if err != nil {
		Log.LogError(fmt.Sprintf("An error happened during the redirection. %v", err))
		rw.WriteHeader(http.StatusBadGateway)
		// TODO log into airbrake when airbrake is supported
		return
	}
	Log.LogInformation(fmt.Sprintf("Response received with status code %d", resp.StatusCode))
	for key := range resp.Header {
		value := resp.Header.Get(key)
		rw.Header().Add(key, value)
	}
	rw.WriteHeader(resp.StatusCode)
	_, err = io.Copy(rw, resp.Body)
	if err != nil {
		Log.LogError(fmt.Sprintf("An error happened during the copy of http response. %v", err))
		rw.WriteHeader(http.StatusBadGateway)
		resp.Body.Close()
		// TODO log into airbrake when airbrake is supported
		return
	}
	resp.Body.Close()
}

func (r *redirectionInfo) ToUrl() string {
	urlString := r.scheme + "://" + r.host + r.path
	if r.rawQuery != "" {
		urlString += "?" + r.rawQuery
	}
	return urlString
}

func (r *redirectionInfo) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	destinationUrl := r.ToUrl()
	if r.routingMethod == RoutingMethodDirectCall {
		proxyHTTPRequest(rw, req, destinationUrl)
	} else {
		if req.Method == http.MethodOptions {
			proxyHTTPRequest(rw, req, destinationUrl)
			return
		}
		rw.Header().Set("Location", destinationUrl)
		if origin := req.Header.Get("Origin"); origin != "" {
			rw.Header().Set("Access-Control-Allow-Origin", origin)
			rw.Header().Set("Access-Control-Request-Method", "*")
			rw.Header().Set("Access-Control-Request-Headers", "*")
		}

		status := http.StatusFound
		if req.Method != http.MethodGet {
			status = http.StatusTemporaryRedirect
		}
		rw.WriteHeader(status)
		_, err := rw.Write([]byte(http.StatusText(status)))
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (a *RegionalRouter) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if isGlobalHost(req.Host, a.globalHostUrls) {
		Log.LogInformation(fmt.Sprintf("Handle current host: %s", req.Host))
		for i := 0; i < len(a.matchPaths); i++ {
			matchPath := a.matchPaths[i]
			if isMatching(&matchPath, req) {
				var newLocation *redirectionInfo
				var err error
				switch matchPath.matchType {
				case MatchPathTypeJwt:
					newLocation, err = handleJwtRedirection(req, a)
					if err != nil {
						Log.LogError(fmt.Sprintf("%v", err))
						// TODO log into airbrake when airbrake is supported
						break
					}
				case MatchPathTypePath:
					newLocation, err = handlePathRedirection(&matchPath, req, a)
					if err != nil {
						Log.LogError(fmt.Sprintf("%v", err))
						// TODO log into airbrake when airbrake is supported
						break
					}
				}
				if newLocation != nil {
					newLocation.ServeHTTP(rw, req)
					return
				}
			}
		}
	}
	a.next.ServeHTTP(rw, req)
}
