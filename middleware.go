package TraefikRegionalPlugin

import (
	"context"
	"errors"
	"fmt"
	"github.com/finalcad/TraefikRegionalPlugin/regional_uuid"
	"net/http"
	"regexp"
)

// Config
type MatchPathRegexConfig struct {
	Regex string `json:"regex,omitempty"`
	Index int    `json:"index,omitempty"`
}
type DestinationHostConfig struct {
	Host 		string `json:"host,omitempty"`
	Value 		int `json:"value,omitempty"`
	IsCurrent 	bool `json:"is_current,omitempty"`
}
type Config struct {
	GlobalHostUrls 			[]string `json:"global_host_urls,omitempty"`
	MatchPaths 				[]MatchPathRegexConfig `json:"match_urls,omitempty"`
	DestinationHosts 		[]DestinationHostConfig `json:"destination_hosts,omitempty"`
	IsLittleEndian			bool `json:"little_endian,omitempty"`
	DefaultScheme			string `json:"default_schema,omitempty"`
}



// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		GlobalHostUrls: make([]string, 0),
		MatchPaths: make([]MatchPathRegexConfig, 0),
		DestinationHosts: make([]DestinationHostConfig, 0),
		IsLittleEndian: true,
		DefaultScheme: "https",
	}
}

type MatchPathRegex struct {
	stringRegex 	string
	regex 			*regexp.Regexp
	index 			int
}
type DestinationHost struct {
	host 		string
	value 		int
	isCurrent 	bool
}

type RegionalRouter struct {
	next         		http.Handler
	globalHostUrls 		[]string
	matchPaths 			[]MatchPathRegex
	destinationHosts 	[]DestinationHost
	defaultScheme		string
	isLittleEndian		bool
	name         		string
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
		fmt.Printf("MatchPath: %s %d\n", config.MatchPaths[i].Regex, config.MatchPaths[i].Index)
		matchPathRegexp = append(matchPathRegexp, MatchPathRegex{regex: regex, index: config.MatchPaths[i].Index, stringRegex: config.MatchPaths[i].Regex})
	}

	fmt.Printf("Destination hosts (%d)\n", len(config.DestinationHosts))
	var destinationHosts []DestinationHost
	for i := 0; i < len(config.DestinationHosts); i++ {
		fmt.Printf("Destination host: %s %d\n", config.DestinationHosts[i].Host, config.DestinationHosts[i].Value)
		destinationHosts = append(destinationHosts, DestinationHost{
			host:  config.DestinationHosts[i].Host,
			value: config.DestinationHosts[i].Value,
			isCurrent: config.DestinationHosts[i].IsCurrent,
		})
	}
	if config.IsLittleEndian {
		fmt.Printf("Endianness set to little\n")
	} else {
		fmt.Printf("Endianness set to big\n")
	}

	return &RegionalRouter{
		globalHostUrls:  config.GlobalHostUrls,
		matchPaths: matchPathRegexp,
		destinationHosts: destinationHosts,
		isLittleEndian: config.IsLittleEndian,
		defaultScheme: config.DefaultScheme,
		next:     next,
		name:     name,
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

func (a *RegionalRouter) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if isGlobalHost(req.Host, a.globalHostUrls) {
		fmt.Printf("Handle current host: %s\n", req.Host)
		for i := 0; i < len(a.matchPaths); i++ {
			matchPath := a.matchPaths[i]
			fmt.Printf("Try regex: %s on path: %s with result: %t\n", matchPath.stringRegex, req.URL.Path, matchPath.regex.MatchString(req.URL.Path))
			if matchPath.regex.MatchString(req.URL.Path) {
				fmt.Printf("The current Path `%s` match with url rewrite rules\n", req.URL.Path)
				subMatch := matchPath.regex.FindStringSubmatch(req.URL.Path)
				if len(subMatch) >= matchPath.index + 1 {
					rUuid, err := regional_uuid.Regional.Read(subMatch[matchPath.index+1], a.isLittleEndian)
					if err != nil {
						break
					}
					regionHost, err := findRegionHost(rUuid.Region, a.destinationHosts, req.Host)
					if err == nil && regionHost != req.Host {
						var newLocation string
						if req.URL.Scheme != "" {
							newLocation =  req.URL.Scheme + "://" + regionHost + req.URL.Path
						} else {
							newLocation = a.defaultScheme + "://" + regionHost + req.URL.Path
						}

						fmt.Printf("New location: %s\n", newLocation)
						rw.Header().Add("Location", newLocation)
						rw.WriteHeader(http.StatusTemporaryRedirect)
						return
					}
				}
			}
		}
	}

	a.next.ServeHTTP(rw, req)
}
