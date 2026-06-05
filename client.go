package safeurl

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	urllib "net/url"
	"strings"
	"syscall"
)

func buildHttpClient(wc *WrappedClient) (*http.Client, error) {
	transport := &http.Transport{}
	if wc.transport != nil {
		if wc.transport.DialContext != nil {
			return nil, &UnsupportedTransportError{field: "DialContext"}
		}
		if wc.transport.DialTLSContext != nil {
			return nil, &UnsupportedTransportError{field: "DialTLSContext"}
		}
		transport = wc.transport.Clone()
	}
	if wc.tlsConfig != nil {
		transport.TLSClientConfig = wc.tlsConfig
	}
	transport.DialContext = (&net.Dialer{
		Resolver: wc.resolver,
		Control:  buildRunFunc(wc),
	}).DialContext

	client := &http.Client{
		Timeout:       wc.config.Timeout,
		CheckRedirect: wc.config.CheckRedirect,
		Jar:           wc.config.Jar,
		Transport:     transport,
	}

	return client, nil
}

func buildRunFunc(wc *WrappedClient) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		wc.log(fmt.Sprintf("connection to address: %v", address))

		if !wc.config.IsIPv6Enabled && network == "tcp6" {
			wc.log("ipv6 is disabled")
			return &IPv6BlockedError{ip: address}
		}

		host, port, err := net.SplitHostPort(address)
		if err != nil {
			wc.log(fmt.Sprintf("invalid address format: %v", err))
			return err
		}

		if err = checkPortAllowed(port, wc.config.AllowedPorts); err != nil {
			wc.log(fmt.Sprintf("disallowed port: %v", port))
			return err
		}

		ip := net.ParseIP(host)
		if ip == nil {
			wc.log(fmt.Sprintf("invalid dial host: %v", host))
			return &InvalidHostError{host: host}
		}

		if isIPAllowed(ip, wc.config.AllowedIPs, wc.config.AllowedIPsCIDR) {
			return nil
		}

		// allowlist set in the config, but target IP was not found on the list
		isConfigAllowListSet := wc.config.AllowedIPs != nil || wc.config.AllowedIPsCIDR != nil
		if isConfigAllowListSet {
			wc.log(fmt.Sprintf("ip: %v not found in allowlist", ip))
			return &AllowedIPError{ip: ip.String()}
		}

		if isIPBlocked(ip, wc.config.BlockedIPs, wc.config.BlockedIPsCIDR) {
			wc.log(fmt.Sprintf("ip: %v found in blocklist", ip))
			return &AllowedIPError{ip: ip.String()}
		}

		return nil
	}
}

/* validators */

func validateCredentials(parsed *urllib.URL, config *Config, debugLogFunc func(string)) error {
	if config.AllowSendingCredentials {
		return nil
	}

	username := strings.TrimSpace(parsed.User.Username())
	password, _ := parsed.User.Password()
	password = strings.TrimSpace(password)

	if username != "" || password != "" {
		debugLogFunc("credentials found in supplied url.")
		return &SendingCredentialsBlockedError{}
	}

	return nil
}

func isSchemeValid(parsed *urllib.URL, config *Config, debugLogFunc func(string)) error {
	scheme := parsed.Scheme
	if len(scheme) > 0 && !isSchemeAllowed(scheme, config.AllowedSchemes) {
		debugLogFunc(fmt.Sprintf("disallowed scheme: %v", scheme))
		return &AllowedSchemeError{scheme: scheme}
	}
	return nil
}

func isHostValid(parsed *urllib.URL, config *Config, debugLogFunc func(string)) error {
	host := parsed.Hostname()
	if host == "" {
		debugLogFunc("empty host received")
		return &InvalidHostError{host: ""}
	}

	// IPv6 zone identifiers (e.g. [::ffff:127.0.0.1%any]) are accepted by url.Parse but can
	// produce unparseable dial addresses such as 127.0.0.1%any in the Control hook.
	if strings.Contains(host, "%") {
		debugLogFunc(fmt.Sprintf("host zone identifier not allowed: %s", host))
		return &InvalidHostError{host: host}
	}

	if config.AllowedHosts != nil && !isAllowedHost(host, config.AllowedHosts) {
		debugLogFunc(fmt.Sprintf("disallowed host: %s", host))
		return &AllowedHostError{host: host}
	}

	return nil
}

/* wrapper */

type WrappedClient struct {
	Client *http.Client

	config    *Config
	transport *http.Transport
	tlsConfig *tls.Config
	resolver  *net.Resolver

	// used for track DNS resolutions for testing purposes
	tracer *tracer
}

func Client(config *Config) (*WrappedClient, error) {
	tlsConfig := config.TlsConfig
	transport := config.Transport

	var resolver *net.Resolver = nil
	if config.InTestMode {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "udp", "localhost:8053")
			},
		}
	}

	wc := &WrappedClient{
		config:    config,
		transport: transport,
		tlsConfig: tlsConfig,
		resolver:  resolver,
	}

	httpClient, err := buildHttpClient(wc)
	if err != nil {
		return nil, err
	}
	wc.Client = httpClient
	return wc, nil
}

func (wc *WrappedClient) Head(url string) (resp *http.Response, err error) {
	wc.log("calling proxied Head...")

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}

	return wc.Do(req)
}

func (wc *WrappedClient) Get(url string) (resp *http.Response, err error) {
	wc.log("calling proxied Get...")

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	return wc.Do(req)
}

func (wc *WrappedClient) Post(url string, contentType string, body io.Reader) (resp *http.Response, err error) {
	wc.log("calling proxied Post...")

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}

	return wc.Do(req)
}

func (wc *WrappedClient) PostForm(url string, data urllib.Values) (resp *http.Response, err error) {
	return wc.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}

func (wc *WrappedClient) Do(req *http.Request) (resp *http.Response, err error) {
	wc.log("calling proxied Do...")

	if wc.config.InTestMode {
		wc.tracer = &tracer{}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), wc.tracer.buildTracer()))
	}

	url := req.URL.String()

	parsedURL, err := urllib.Parse(url)

	if err != nil {
		return nil, err
	}

	err = validateCredentials(parsedURL, wc.config, wc.log)
	if err != nil {
		return nil, err
	}

	err = isSchemeValid(parsedURL, wc.config, wc.log)
	if err != nil {
		return nil, err
	}

	err = isHostValid(parsedURL, wc.config, wc.log)
	if err != nil {
		return nil, err
	}

	return wc.Client.Do(req)
}

func (wc *WrappedClient) CloseIdleConnections() {
	wc.Client.CloseIdleConnections()
}

/* testing */

type tracer struct {
	dnsResolutionsCount int
}

func (t *tracer) buildTracer() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
			t.dnsResolutionsCount++
		},
	}
}

/* error */

type AllowedPortError struct {
	port string
}

func (e *AllowedPortError) Error() string {
	return fmt.Sprintf("port: %v not found in allowlist", e.port)
}

type AllowedSchemeError struct {
	scheme string
}

func (e *AllowedSchemeError) Error() string {
	return fmt.Sprintf("scheme: %v not found in allowlist", e.scheme)
}

type InvalidHostError struct {
	host string
}

func (e *InvalidHostError) Error() string {
	return fmt.Sprintf("host: %v is not valid", e.host)
}

type AllowedHostError struct {
	host string
}

func (e *AllowedHostError) Error() string {
	return fmt.Sprintf("host: %v not found in allowlist", e.host)
}

type AllowedIPError struct {
	ip string
}

func (e *AllowedIPError) Error() string {
	return fmt.Sprintf("ip: %v not found in allowlist", e.ip)
}

type IPv6BlockedError struct {
	ip string
}

func (e *IPv6BlockedError) Error() string {
	return fmt.Sprintf("ipv6 blocked. connection to %v dropped", e.ip)
}

type SendingCredentialsBlockedError struct {
}

func (e *SendingCredentialsBlockedError) Error() string {
	return fmt.Sprintf("sending credentials blocked.")
}

type UnsupportedTransportError struct {
	field string
}

func (e *UnsupportedTransportError) Error() string {
	return fmt.Sprintf("custom %s not supported", e.field)
}

func unwrap(err error) error {
	wrapped, ok := err.(interface{ Unwrap() error })
	if !ok {
		return err
	}
	inner := wrapped.Unwrap()
	return unwrap(inner)
}

/* debug */

func (wc *WrappedClient) log(msg string) {
	if wc.config.IsDebugLoggingEnabled {
		fmt.Printf("[safeurl] %v\n", msg)
	}
}
