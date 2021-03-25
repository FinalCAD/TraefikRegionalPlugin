package TraefikRegionalPlugin

import (
	"context"
	"errors"
	"fmt"
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

type Config struct {
	GlobalHostUrls   []string                `json:"global_host_urls,omitempty"`
	MatchPaths       []MatchPathRegexConfig  `json:"match_urls,omitempty"`
	DestinationHosts []DestinationHostConfig `json:"destination_hosts,omitempty"`
	IsLittleEndian   bool                    `json:"little_endian,omitempty"`
	DefaultScheme    string                  `json:"default_schema,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		GlobalHostUrls:   make([]string, 0),
		MatchPaths:       make([]MatchPathRegexConfig, 0),
		DestinationHosts: make([]DestinationHostConfig, 0),
		IsLittleEndian:   true,
		DefaultScheme:    "https",
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

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	var matchPathRegexp []MatchPathRegex

	fmt.Println("New: Load configuration")

	fmt.Printf("GlobalHosts (%d) from config\n", len(config.GlobalHostUrls))
	for i := 0; i < len(config.GlobalHostUrls); i++ {
		fmt.Printf("GlobalHost: %s\n", config.GlobalHostUrls[i])
	}

	for i := 0; i < len(config.MatchPaths); i++ {
		regex, err := regexp.Compile(config.MatchPaths[i].Regex)
		if err != nil {
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
			fmt.Printf("MatchPath JWT: %s %d\n", config.MatchPaths[i].Regex, config.MatchPaths[i].Index)
		} else if config.MatchPaths[i].Type == MatchPathTypePath {
			fmt.Printf("MatchPath UUID: %s %d\n", config.MatchPaths[i].Regex, config.MatchPaths[i].Index)
		} else {
			fmt.Printf("Unknown type %s. The regex %s is ignored", config.MatchPaths[i].Type, config.MatchPaths[i].Regex)
			continue
		}
		matchPathRegexp = append(matchPathRegexp, matchPathRegex)
	}

	fmt.Printf("Destination hosts (%d)\n", len(config.DestinationHosts))
	var destinationHosts []DestinationHost
	for i := 0; i < len(config.DestinationHosts); i++ {
		fmt.Printf("Destination host: %s %d\n", config.DestinationHosts[i].Host, config.DestinationHosts[i].Value)
		destinationHosts = append(destinationHosts, DestinationHost{
			host:      config.DestinationHosts[i].Host,
			value:     config.DestinationHosts[i].Value,
			isCurrent: config.DestinationHosts[i].IsCurrent,
		})
	}
	if config.IsLittleEndian {
		fmt.Printf("Endianness set to little\n")
	} else {
		fmt.Printf("Endianness set to big\n")
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
	fmt.Printf("Try regex: %s on path: %s with result: %t\n", matchPath.stringRegex, req.URL.Path, matchPath.regex.MatchString(req.URL.Path))
	if matchPath.regex.MatchString(req.URL.Path) {
		if matchPath.methods != nil && len(matchPath.methods) > 0 {
			fmt.Printf("Filter by methods\n")
			for _, value := range matchPath.methods {
				if value == req.Method {
					fmt.Printf("The current Path `%s` `%s` match with url rewrite rules\n", req.Method, req.URL.Path)
					return true
				}
			}
		} else {
			fmt.Printf("The current Path `%s` match with url rewrite rules\n", req.URL.Path)
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

		fmt.Printf("New location: %s\n", newLocation)
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
	token, err := jwt.Parse(authorizationToken)
	if err != nil {
		fmt.Printf("Fail to parse jwt. Missing or invalid\n")
		return nil, err
	}
	if token != nil {
		value, contain := token.Payload[JwtClaimUserId]
		if contain {
			fmt.Printf("Token found with userId=%s\n", value)
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
		fmt.Printf("Handle current host: %s\n", req.Host)
		for i := 0; i < len(a.matchPaths); i++ {
			matchPath := a.matchPaths[i]
			if isMatching(&matchPath, req) {
				var newLocation *string
				var err error
				switch matchPath.matchType {
				case MatchPathTypeJwt:
					newLocation, err = handleJwtRedirection(req, a)
					if err != nil {
						// todo log into airbrake
						break
					}
				case MatchPathTypePath:
					newLocation, err = handlePathRedirection(&matchPath, req, a)
					if err != nil {
						// todo log into airbrake
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
