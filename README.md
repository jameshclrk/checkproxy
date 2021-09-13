# Check Proxy
[![codecov](https://codecov.io/gh/jameshclrk/checkproxy/branch/main/graph/badge.svg?token=4VUU7B25Z2)](https://codecov.io/gh/jameshclrk/checkproxy)

This is a middleware for `net/http` which checks the `RemoteAddr` in the request and compares it against a list of trusted proxies.

The middleware has two arguments:
 - `useProxy: bool` - If true, we are expecting a proxy and the `RemoteAddr` is checked. If false, we are not expecting a proxy.
 - `trustedProxies: []string` - The list of trusted IP addresses or CIDR blocks

## How to use
Add to your imports and use the middleware with your `net/http` compatible router.

For example, with [go-chi](https://github.com/go-chi/chi):

```go
import (
	...
	"github.com/jameshclrk/checkproxy"
)
...
r := chi.NewRouter()
r.Use(checkproxy.CheckProxy(true, []string{"10.0.0.0/24", "192.168.0.1"}))
...
```

## Custom Error Function
Sometimes it is useful to use a custom function when an error occurs. For example, the `CheckProxy` middleware should be used early in the chain (before assigning the `X-Forwarded-For` header to the `RemoteAddr`) which may be before the logging middleware. In this case, the logging middleware may be skipped on an error. So we can write a custom error function that logs for us!

This example uses the go-chi `Logger` and `RealIP` middleware.

```go
...
logger := middleware.DefaultLogFormatter{Logger: log.New(os.Stdout, "", log.LstdFlags), NoColor: !true}
checker := checkproxy.ProxyChecker{
	UseProxy:       useProxy,
	TrustedProxies: trustedProxies,
	ErrorFunc: func(s int, m string, w http.ResponseWriter, r *http.Request) {
		entry := logger.NewLogEntry(r)
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		t1 := time.Now()
		defer func() {
			entry.Write(ww.Status(), ww.BytesWritten(), ww.Header(), time.Since(t1), nil)
		}()
		ww.WriteHeader(s)
		ww.Write([]byte(m))
	},
}
r := chi.NewRouter()
r.Use(checker.Handle)
r.Use(middleware.RealIP)
r.Use(middleware.RequestLogger(logger))
...
```
