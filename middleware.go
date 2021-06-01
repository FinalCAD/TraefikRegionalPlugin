package TraefikRegionalPlugin

import (
	"context"
	"errors"
	"fmt"
	"github.com/finalcad/TraefikRegionalPlugin/jwt"
	"github.com/finalcad/TraefikRegionalPlugin/regional_uuid"
	"io"
	"net/http"
	"net/url"
	"regexp"
)

const (
	MatchPathTypePath = "PATH"
	MatchPathTypeJwt  = "JWT"
	JwtClaimUserId    = "fcUserId"
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
	}
}

type MatchPathRegex struct {
	stringRegex string
	regex       *regexp.Regexp
	matchType   string
	index       int
	methods     []string
}
type DestinationHost struct {
	host      string
	value     int
	isCurrent bool
}

type RegionalRouter struct {
	next             http.Handler
	globalHostUrls   []string
	matchPaths       []MatchPathRegex
	destinationHosts []DestinationHost
	defaultScheme    string
	isLittleEndian   bool
	name             string
}

type redirectionInfo struct {
	Scheme string
	Host   string
	Path   string
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	var matchPathRegexp []MatchPathRegex

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
		matchPathRegex := MatchPathRegex{
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
	var destinationHosts []DestinationHost
	for i := 0; i < len(config.DestinationHosts); i++ {
		Log.LogDebug(fmt.Sprintf("Destination host: Host=%s Region=%d", config.DestinationHosts[i].Host, config.DestinationHosts[i].Value))
		destinationHosts = append(destinationHosts, DestinationHost{
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

	return &RegionalRouter{
		globalHostUrls:   config.GlobalHostUrls,
		matchPaths:       matchPathRegexp,
		destinationHosts: destinationHosts,
		isLittleEndian:   config.IsLittleEndian,
		defaultScheme:    config.DefaultScheme,
		next:             next,
		name:             name,
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

func findRegionHost(region byte, hosts []DestinationHost, previousHost string) (string, error) {
	for i := 0; i < len(hosts); i++ {
		if int(region) == hosts[i].value {
			if hosts[i].isCurrent {
				return previousHost, nil
			}
			return hosts[i].host, nil
		}
	}
	return "", errors.New("no region found")
}

func isMatching(matchPath *MatchPathRegex, req *http.Request) bool {
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
	if err == nil && regionHost != req.Host {
		newLocation := &redirectionInfo{
			Host:   regionHost,
			Path:   req.URL.Path,
			Scheme: "http",
		}

		if req.TLS != nil {
			newLocation.Scheme = "https"
		}

		Log.LogInformation(fmt.Sprintf("Redirection to location: %s://%s%s", newLocation.Scheme, newLocation.Host, newLocation.Path))
		return newLocation, nil
	}
	return nil, nil
}

func handlePathRedirection(matchPath *MatchPathRegex,
	req *http.Request,
	regionalRouter *RegionalRouter) (*redirectionInfo, error) {
	subMatch := matchPath.regex.FindStringSubmatch(req.URL.Path)
	if len(subMatch) >= matchPath.index+1 {
		rUuid, err := regional_uuid.Regional.Read(subMatch[matchPath.index+1], regionalRouter.isLittleEndian)
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
					parsedURL, err := url.Parse(newLocation.Scheme + "://" + newLocation.Host + newLocation.Path)
					if err != nil {
						Log.LogError(fmt.Sprintf("%v", err))
						a.next.ServeHTTP(rw, req)
						return
					}
					reqClone := req.Clone(context.TODO())
					reqClone.URL = parsedURL
					reqClone.Host = newLocation.Host
					reqClone.RequestURI = ""
					reqClone.Header.Set("X-Forwarded-Host", req.Host)
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
					return
				}
			}
		}
	}

	a.next.ServeHTTP(rw, req)
}
