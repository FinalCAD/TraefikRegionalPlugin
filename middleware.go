package TraefikRegionalPlugin

import (
	"context"
	"errors"
	"fmt"
	"github.com/airbrake/gobrake/v5"
	"github.com/finalcad/TraefikRegionalPlugin/jwt"
	"github.com/finalcad/TraefikRegionalPlugin/regional_uuid"
	"net/http"
	"regexp"
)

const (
	MatchPathTypePath = "PATH"
	MatchPathTypeJwt  = "JWT"
	JwtClaimUserId    = "fcUserId"
)

// Config
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

type AirbrakeConfig struct {
	ProjectId   int64  `json:"project_id,omitempty"`
	ProjectKey  string `json:"project_key,omitempty"`
	Environment string `json:"environment,omitempty"`
}

type Config struct {
	GlobalHostUrls   []string                `json:"global_host_urls,omitempty"`
	MatchPaths       []MatchPathRegexConfig  `json:"match_urls,omitempty"`
	DestinationHosts []DestinationHostConfig `json:"destination_hosts,omitempty"`
	IsLittleEndian   bool                    `json:"little_endian,omitempty"`
	DefaultScheme    string                  `json:"default_schema,omitempty"`
	Log              string                  `json:"log,omitempty"`
	Airbrake         AirbrakeConfig          `json:"airbrake,omitempty"`
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
	airbrake         *gobrake.Notifier
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	var matchPathRegexp []MatchPathRegex

	Log.SetLevel(config.Log)

	Log.LogInformation("Load configuration")
	var airbrake *gobrake.Notifier = nil
	if config.Airbrake.ProjectId != 0 &&
		config.Airbrake.ProjectKey != "" &&
		config.Airbrake.Environment != "" {
		Log.LogInformation("Load airbrake for reporting error")
		airbrake = gobrake.NewNotifierWithOptions(&gobrake.NotifierOptions{
			ProjectId:   config.Airbrake.ProjectId,
			ProjectKey:  config.Airbrake.ProjectKey,
			Environment: config.Airbrake.Environment,
		})
	}

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
			Log.LogWarning(fmt.Sprintf("\tUnknown type %s. The regex %s is ignored", config.MatchPaths[i].Type, config.MatchPaths[i].Regex))
			continue
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
		airbrake:         airbrake,
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
	regionalRouter *RegionalRouter) (*string, error) {
	regionHost, err := findRegionHost(region, regionalRouter.destinationHosts, req.Host)
	if err == nil && regionHost != req.Host {
		var newLocation string
		if req.URL.Scheme != "" {
			newLocation = req.URL.Scheme + "://" + regionHost + req.URL.Path
		} else {
			newLocation = regionalRouter.defaultScheme + "://" + regionHost + req.URL.Path
		}

		Log.LogInformation(fmt.Sprintf("Redirection to location: %s", newLocation))
		return &newLocation, nil
	}
	return nil, nil
}

func handlePathRedirection(matchPath *MatchPathRegex,
	req *http.Request,
	regionalRouter *RegionalRouter) (*string, error) {
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
	regionalRouter *RegionalRouter) (*string, error) {
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
				var newLocation *string
				var err error
				switch matchPath.matchType {
				case MatchPathTypeJwt:
					newLocation, err = handleJwtRedirection(req, a)
					if err != nil {
						Log.LogError(fmt.Sprintf("%v", err))
						if a.airbrake != nil {
							a.airbrake.Notify(err, req)
						}
						break
					}
				case MatchPathTypePath:
					newLocation, err = handlePathRedirection(&matchPath, req, a)
					if err != nil {
						Log.LogError(fmt.Sprintf("%v", err))
						if a.airbrake != nil {
							a.airbrake.Notify(err, req)
						}
						break
					}
				}
				if newLocation != nil {
					rw.Header().Add("Location", *newLocation)
					rw.WriteHeader(http.StatusTemporaryRedirect)
					return
				}
			}
		}
	}

	a.next.ServeHTTP(rw, req)
}
