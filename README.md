# clients

A Go package providing HTTP(S) client utilities based on [resty](https://github.com/go-resty/resty), with support for custom TLS configuration, proxy, random User-Agent, protocol detection, and convenient HTTP request helpers.

## Features

- Custom TLS configuration (supports insecure HTTPS, legacy ciphers)
- Bind outgoing requests to a specific local IP
- Proxy support
- Random User-Agent for each request
- Protocol detection (auto-detect HTTP/HTTPS)
- Simple helpers for GET/POST and header parsing
- Automatic GBK to UTF-8 conversion for Chinese web pages

## Installation

```
go get github.com/yourusername/clients
```

## Usage

```go
package main

import (
	"fmt"
	"github.com/yourusername/clients"
)

func main() {
	client := clients.DefaultRestyClient()
	resp, err := clients.SimpleGet("https://example.com", client)
	if err != nil {
		panic(err)
	}
	fmt.Println("Status:", resp.Status())
	fmt.Println("Title:", clients.GetTitle(resp.Body()))
}
```

### Custom Client with Proxy and Local IP

```go
import (
	"net"
	"github.com/yourusername/clients"
)

ip := net.ParseIP("192.168.1.100")
client := clients.NewRestyClientWithProxy(ip, true, "http://127.0.0.1:8080")
```

### Protocol Detection

```go
url, err := clients.CheckProtocol("example.com", client)
if err != nil {
	panic(err)
}
fmt.Println("Detected URL:", url)
```

## API Reference

- `DefaultRestyClient() *resty.Client` — Default HTTP client
- `NewRestyClient(interfaceIp net.IP, followRedirect bool) *resty.Client` — Custom client
- `NewRestyClientWithProxy(interfaceIp net.IP, followRedirect bool, proxyURL string) *resty.Client` — With proxy
- `DoRequest(method, url string, headers map[string]string, body io.Reader, timeout int, client *resty.Client) (*resty.Response, error)` — Generic request
- `SimpleGet(url string, client *resty.Client) (*resty.Response, error)` — Simple GET
- `GetTitle(body []byte) string` — Extract HTML title
- `Str2UTF8(str string) string` — Convert to UTF-8
- `Str2HeadersMap(str string) map[string]string` — Parse headers
- `Str2HeaderList(str string) []string` — Header list
- `RandomUA() string` — Random User-Agent
- `CheckProtocol(host string, client *resty.Client) (string, error)` — Detect protocol

## Dependencies

- [go-resty/resty](https://github.com/go-resty/resty)
- [golang.org/x/text/encoding/simplifiedchinese](https://pkg.go.dev/golang.org/x/text/encoding/simplifiedchinese)

## FAQ

**Q: Why does it allow insecure HTTPS?**  
A: For compatibility with legacy or misconfigured servers. You can change `TlsConfig` as needed.

**Q: How to use with a proxy?**  
A: Use `NewRestyClientWithProxy` and provide your proxy URL.

**Q: How to bind to a specific local IP?**  
A: Pass your local IP to `NewRestyClient` or `NewRestyClientWithProxy`.

## License

MIT 