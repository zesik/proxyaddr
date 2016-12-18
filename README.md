# proxyaddr

[![GoDoc](https://godoc.org/github.com/zesik/proxyaddr?status.svg)](https://godoc.org/github.com/zesik/proxyaddr)
[![Build Status](https://travis-ci.org/zesik/proxyaddr.svg?branch=master)](https://travis-ci.org/zesik/proxyaddr)
[![Coverage Status](https://coveralls.io/repos/github/zesik/proxyaddr/badge.svg?branch=master)](https://coveralls.io/github/zesik/proxyaddr?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/zesik/proxyaddr)](https://goreportcard.com/report/github.com/zesik/proxyaddr)

Package `proxyaddr` is a middleware for determining client address for proxied requests in Go.

After `proxyaddr` is set with trusted proxies (such as local nginx, HAProxy, etc.),
it tries to get the actual IP address of clients from `x-forwarded-for` HTTP header.
If presents, `proxyaddr` sets the IP address to `RemoteAddr` field of the `http.Request` instance.
Note the port number in `RemoteAddr` is left unchanged.

## Install

```
go get github.com/zesik/proxyaddr
```

## Quick Example

Using with standard `net/http`:

```go
package main

import (
	"net/http"

	"github.com/zesik/proxyaddr"
)

func main() {
	pa := &proxyaddr.ProxyAddr{}
	pa.Init(proxyaddr.CIDRLoopback)
	http.ListenAndServe(":8080", pa.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.RemoteAddr))
	})))
}
```

Using with Negroni:

```go
package main

import (
	"net/http"

	"github.com/urfave/negroni"
	"github.com/zesik/proxyaddr"
)

func main() {
	pa := &proxyaddr.ProxyAddr{}
	pa.Init(proxyaddr.CIDRLoopback)

	n := negroni.New()
	n.Use(pa)
	n.UseHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.RemoteAddr))
	}))

	http.ListenAndServe(":8080", n)
}
```

A quick test with curl:

```
$ curl localhost:8080
[::1]:53998

$ curl -H "x-forwarded-for: 1.2.3.4, 5.6.7.8" localhost:8080
5.6.7.8:53999
```

## License

[MIT](LICENSE)
