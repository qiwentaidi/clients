// Package clients provides HTTP(S) client utilities based on resty, with support for custom TLS, proxy, random User-Agent, and protocol detection.
package clients

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-resty/resty/v2"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// TlsConfig is a custom TLS configuration that allows insecure HTTPS connections and supports a wide range of cipher suites.
var TlsConfig = &tls.Config{
	InsecureSkipVerify: true,             // 防止HTTPS报错
	MinVersion:         tls.VersionTLS10, // 最低支持TLS 1.0
	CipherSuites: []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	},
}

// NewRestyClient creates a new resty.Client with optional local interface IP and redirect policy.
// If interfaceIp is not nil, the client will bind to the specified local IP.
// If followRedirect is true, the client will follow up to 10 redirects.
func NewRestyClient(interfaceIp net.IP, followRedirect bool) *resty.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	if interfaceIp != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: interfaceIp}
	}

	transport := &http.Transport{
		TLSClientConfig:       TlsConfig,
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := resty.New().
		SetTransport(transport).
		SetTimeout(10*time.Second).
		SetHeader("User-Agent", RandomUA()).
		SetHeader("Connection", "close")
	// 设置重定向规则
	if followRedirect {
		client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(10))
	} else {
		client.SetRedirectPolicy(resty.NoRedirectPolicy())
	}
	return client
}

// DefaultRestyClient returns a resty.Client with default settings (no local IP, follow redirects).
func DefaultRestyClient() *resty.Client {
	return NewRestyClient(nil, true)
}

// NewRestyClientWithProxy creates a new resty.Client with optional local interface IP, redirect policy, and proxy URL.
// If proxyURL is not empty, the client will use the specified proxy.
func NewRestyClientWithProxy(interfaceIp net.IP, followRedirect bool, proxyURL string) *resty.Client {
	client := NewRestyClient(interfaceIp, followRedirect)
	if proxyURL != "" {
		client.SetProxy(proxyURL)
	}
	return client
}

// DoRequest performs an HTTP request with the specified method, URL, headers, body, and timeout using the provided resty.Client.
// Returns the response or an error.
func DoRequest(method, url string, headers map[string]string, body io.Reader, timeout int, client *resty.Client) (*resty.Response, error) {
	if timeout > 0 {
		client.SetTimeout(time.Duration(timeout) * time.Second)
	}

	req := client.R()

	if headers != nil {
		req.SetHeaders(headers)
	}

	if body != nil {
		// 将 io.Reader 转换为 []byte 读入
		data, err := io.ReadAll(body)
		if err != nil {
			return nil, fmt.Errorf("read body failed: %w", err)
		}
		req.SetBody(data)
	}

	var resp *resty.Response
	var err error

	switch method {
	case http.MethodGet:
		resp, err = req.Get(url)
	case http.MethodPost:
		resp, err = req.Post(url)
	case http.MethodPut:
		resp, err = req.Put(url)
	case http.MethodDelete:
		resp, err = req.Delete(url)
	case http.MethodPatch:
		resp, err = req.Patch(url)
	case http.MethodOptions:
		resp, err = req.Options(url)
	default:
		return nil, fmt.Errorf("unsupported method: %s", method)
	}

	if err != nil {
		return resp, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

// SimpleGet performs a simple GET request to the specified URL using the provided resty.Client.
func SimpleGet(url string, client *resty.Client) (*resty.Response, error) {
	return DoRequest("GET", url, nil, nil, 10, client)
}

// regTitle is a regular expression to extract the <title> tag content from HTML.
var regTitle = regexp.MustCompile(`(?is)<title\b[^>]*>(.*?)</title>`)

// GetTitle extracts and returns the <title> content from the given HTML body.
// If the body is empty or no title is found, returns an empty string.
func GetTitle(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	if match := regTitle.FindSubmatch(body); len(match) > 1 {
		return strings.TrimSpace(Str2UTF8(string(match[1])))
	}
	return ""
}

// Str2UTF8 converts a string to UTF-8 encoding, attempting GBK decoding if the string is not valid UTF-8.
func Str2UTF8(str string) string {
	if len(str) == 0 {
		return ""
	}
	if !utf8.ValidString(str) {
		utf8Bytes, _ := io.ReadAll(transform.NewReader(
			strings.NewReader(str),
			simplifiedchinese.GBK.NewDecoder(),
		))
		return string(utf8Bytes)
	}
	return str
}

// Str2HeadersMap parses a raw HTTP header string into a map[string]string.
// Each line should be in the format 'Key: Value'.
func Str2HeadersMap(str string) map[string]string {
	headers := make(map[string]string)
	if str == "" {
		return headers
	}
	for _, line := range strings.Split(str, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if i := strings.IndexByte(line, ':'); i > 0 {
			headers[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
		}
	}
	return headers
}

// Str2HeaderList splits a raw HTTP header string into a slice of header lines.
func Str2HeaderList(str string) []string {
	headers := make([]string, 0)
	if str == "" {
		return headers
	}
	for _, line := range strings.Split(str, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		headers = append(headers, line)
	}
	return headers
}

// RandomUA returns a random User-Agent string from a predefined list.
func RandomUA() string {
	userAgent := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2919.83 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2866.71 Safari/537.36",
		"Mozilla/5.0 (X11; Ubuntu; Linux i686 on x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2820.59 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2762.73 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2656.18 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/44.0.2403.155 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2226.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2224.3 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.93 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 4.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36",
		"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36",
		"Mozilla/5.0 (X11; OpenBSD i386) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1944.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36",
		"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36",
		"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2117.157 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36",
		"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1866.237 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.137 Safari/4E423F",
	}
	return userAgent[rand.New(rand.NewSource(time.Now().Unix())).Intn(len(userAgent))]
}

const (
	// HTTP_PREFIX is the prefix for HTTP URLs.
	HTTP_PREFIX = "http://"
	// HTTPS_PREFIX is the prefix for HTTPS URLs.
	HTTPS_PREFIX = "https://"
)

// IsHTTPToHTTPSError checks if the response body contains the error indicating an HTTP request was sent to an HTTPS port.
func IsHTTPToHTTPSError(body []byte) bool {
	return strings.Contains(string(body), "400 The plain HTTP request was sent to HTTPS port")
}

// CheckProtocol detects the protocol (HTTP or HTTPS) for the given host and returns the full URL.
// It tries HTTPS first, then HTTP, and checks for common protocol errors.
func CheckProtocol(host string, client *resty.Client) (string, error) {
	var result string

	if len(strings.TrimSpace(host)) == 0 {
		return result, fmt.Errorf("host %q is empty", host)
	}

	if strings.HasPrefix(host, HTTPS_PREFIX) || strings.HasPrefix(host, HTTP_PREFIX) {
		_, err := SimpleGet(host, client)
		if err != nil {
			return result, err
		}
		return host, nil
	}

	u, err := url.Parse(HTTP_PREFIX + host)
	if err != nil {
		return result, err
	}

	switch u.Port() {
	case "80":
		_, err := SimpleGet(HTTP_PREFIX+host, client)
		if err != nil {
			return result, err
		}
		return HTTP_PREFIX + host, nil

	case "443":
		_, err := SimpleGet(HTTPS_PREFIX+host, client)
		if err != nil {
			return result, err
		}
		return HTTPS_PREFIX + host, nil

	default:
		// 先试 https
		_, err := SimpleGet(HTTPS_PREFIX+host, client)
		if err == nil {
			return HTTPS_PREFIX + host, nil
		}
		// 再试 http
		resp, err := SimpleGet(HTTP_PREFIX+host, client)
		if err == nil {
			if IsHTTPToHTTPSError(resp.Body()) {
				return HTTPS_PREFIX + host, nil
			}
			return HTTP_PREFIX + host, nil
		}
	}

	return "", fmt.Errorf("both http and https check failed for host: %s", host)
}
