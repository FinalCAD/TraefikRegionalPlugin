# How to test

This folder contains preconfigured traefik and whoami instance.

## Setup
For Windows user, add this following line into the file `C:\Windows\System32\drivers\etc\hosts`

```
127.0.0.1 api.massive-dynamic.com
127.0.0.1 api.ja.massive-dynamic.com
127.0.0.1 api.na.massive-dynamic.com
```

For Unix user, add this following line into /etc/hosts

```
127.0.0.1 api.massive-dynamic.com
127.0.0.1 api.ja.massive-dynamic.com
127.0.0.1 api.na.massive-dynamic.com
```

## Start

Run `docker-compose up`

## Test

You can now test with any http client.

Example:
```
curl -H "Authorization: Bearer Invalid.Bearer" -X POST http://api.massive-dynamic.com/api/projects/7871f25a-11e65e60-f37b-4e9d-88f5-c6447c91c3a0
```