# How to test

This folder contains preconfigured traefik and whoami instances.

## Start

Run `docker compose up`

## Test

You can now test with any http client.

Example:
```
curl -L -H "Authorization: Bearer Invalid.Bearer" -X POST http://whoami-default.127.0.0.1.nip.io/api/projects/7871f25a-11e65e60-f37b-4e9d-88f5-c6447c91c3a0
```
