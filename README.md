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
