# Traefik Regional plugin

[Traefik](https://traefik.io) plugins are developed using the [Go language](https://golang.org).

A [Traefik](https://traefik.io) middleware plugin is just a [Go package](https://golang.org/ref/spec#Packages) that provides an `http.Handler` to perform specific processing of requests and responses.

Rather than being pre-compiled and linked, however, plugins are executed on the fly by [Yaegi](https://github.com/traefik/yaegi), an embedded Go interpreter.

This plugin redirect on different host when the url match a regex and this regex contains a Extended UUID.

## Usage

For a plugin to be active for a given Traefik instance, it must be declared in the static configuration.

Plugins are parsed and loaded exclusively during startup, which allows Traefik to check the integrity of the code and catch errors early on.
If an error occurs during loading, the plugin is disabled.

For security reasons, it is not possible to start a new plugin or modify an existing one while Traefik is running.

Once loaded, middleware plugins behave exactly like statically compiled middlewares.
Their instantiation and behavior are driven by the dynamic configuration.

Plugin dependencies must be [vendored](https://golang.org/ref/mod#tmp_25) for each plugin.
Vendored packages should be included in the plugin's GitHub repository. ([Go modules](https://blog.golang.org/using-go-modules) are not supported.)

### Configuration

```yaml
# Dynamic configuration

http:
  routers:
    my-router:
      rule: host(`demo.localhost`)
      service: service-foo
      entryPoints:
        - web
      middlewares:
        - TraefikRegionalPlugin

  services:
   service-foo:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:5000
  
  middlewares:
    TraefikRegionalPlugin:
      plugin:
        dev:
          GlobalHostUrls: # list of url for starting detection
            - "whoami.localhost"
          MatchPaths: # Regex to path the path and the index of the group of UUID
            - regex: ^\/project\/(([0-9A-Fa-f]{8}[-]){2,}([0-9A-Fa-f]{4}[-]){3}[0-9A-Fa-f]{12})$
              index: 0
          DestinationHosts: # Destination for redirection based on value extract from UUID
            - host: "whoami.eu.localhost"
              value: 1 # Europe
            - host: "whoami.ap.localhost"
              value: 2 # AsiaPacific
          IsLittleEndian: true # Endianness of the server
```