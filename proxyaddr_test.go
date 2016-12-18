package proxyaddr

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/negroni"
)

func TestInitSingleCIDR(t *testing.T) {
	pa := ProxyAddr{}
	err := pa.Init("10.10.10.0/24")
	assert.NoError(t, err)
	assert.NotNil(t, pa.trustedProxies)
	assert.Len(t, pa.trustedProxies, 1)
	assert.Equal(t, net.IPNet{IP: net.IP{0x0a, 0x0a, 0x0a, 0x00}, Mask: net.IPMask{0xff, 0xff, 0xff, 0x00}},
		*pa.trustedProxies[0])
}

func TestInitMultipleCIDR(t *testing.T) {
	pa := ProxyAddr{}
	err := pa.Init("10.10.10.0/24", "172.27.80.0/20")
	assert.NoError(t, err)
	assert.NotNil(t, pa.trustedProxies)
	assert.Len(t, pa.trustedProxies, 2)
	assert.Equal(t, net.IPNet{IP: net.IP{0x0a, 0x0a, 0x0a, 0x0}, Mask: net.IPMask{0xff, 0xff, 0xff, 0x0}},
		*pa.trustedProxies[0])
	assert.Equal(t, net.IPNet{IP: net.IP{0xac, 0x1b, 0x50, 0x0}, Mask: net.IPMask{0xff, 0xff, 0xf0, 0x0}},
		*pa.trustedProxies[1])
}

func TestInitName(t *testing.T) {
	pa := ProxyAddr{}
	err := pa.Init(CIDRLoopback)
	assert.NoError(t, err)
	assert.NotNil(t, pa.trustedProxies)
	assert.Len(t, pa.trustedProxies, 2)
	assert.Equal(t, net.IPNet{IP: net.IP{0x7f, 0x0, 0x0, 0x0}, Mask: net.IPMask{0xff, 0x0, 0x0, 0x0}},
		*pa.trustedProxies[0])
	assert.Equal(t,
		net.IPNet{
			IP: net.IP{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
			Mask: net.IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		},
		*pa.trustedProxies[1])
}

func TestInitMixedNameAndCIDR(t *testing.T) {
	pa := ProxyAddr{}
	err := pa.Init("192.168.117.0/24", CIDRLoopback, "153.220.34.35/32")
	assert.NoError(t, err)
	assert.NotNil(t, pa.trustedProxies)
	assert.Len(t, pa.trustedProxies, 4)
	assert.Equal(t, net.IPNet{IP: net.IP{0xc0, 0xa8, 0x75, 0x0}, Mask: net.IPMask{0xff, 0xff, 0xff, 0x00}},
		*pa.trustedProxies[0])
	assert.Equal(t, net.IPNet{IP: net.IP{0x99, 0xdc, 0x22, 0x23}, Mask: net.IPMask{0xff, 0xff, 0xff, 0xff}},
		*pa.trustedProxies[3])
}

func TestInitError(t *testing.T) {
	pa := ProxyAddr{}
	err := pa.Init(CIDRUniqueLocal, "192.300.1.0/24")
	assert.Error(t, err)
	assert.Nil(t, pa.trustedProxies)
}

func TestGetRemoteAddrWithNoProxy(t *testing.T) {
	pa := ProxyAddr{}

	r := &http.Request{RemoteAddr: "127.0.0.1:51202"}

	assert.Equal(t, "127.0.0.1:51202", pa.getRemoteAddr(r))
}

func TestGetRemoteAddrWithNoTrustedProxy(t *testing.T) {
	pa := ProxyAddr{}

	r := &http.Request{RemoteAddr: "127.0.0.1:51202", Header: http.Header{"": []string{}}}

	// It should return remote address directly if no header present
	assert.Equal(t, "127.0.0.1:51202", pa.getRemoteAddr(r))

	// It should return remote address even when header presents
	r.Header["X-Forwarded-For"] = []string{"10.0.0.1, 10.0.0.2"}
	assert.Equal(t, "127.0.0.1:51202", pa.getRemoteAddr(r))
}

func TestGetRemoteAddrWithSomeTrustedProxies(t *testing.T) {
	pa := ProxyAddr{}
	err := pa.Init(CIDRLoopback, CIDRUniqueLocal)
	assert.NoError(t, err)

	r := &http.Request{RemoteAddr: "153.220.34.35:51202", Header: http.Header{"": []string{}}}

	// It should return remote address directly if no header present
	assert.Equal(t, "153.220.34.35:51202", pa.getRemoteAddr(r))

	// It should return remote address if it is not trusted
	r.Header["X-Forwarded-For"] = []string{"10.0.0.1"}
	assert.Equal(t, "153.220.34.35:51202", pa.getRemoteAddr(r))

	r.RemoteAddr = "127.0.0.1:51202"

	// It should return header value if remote address is trusted
	r.Header["X-Forwarded-For"] = []string{"10.0.0.1"}
	assert.Equal(t, "10.0.0.1:51202", pa.getRemoteAddr(r))

	// It should return first untrusted value after trusted
	r.Header["X-Forwarded-For"] = []string{"153.220.34.35, 10.0.0.1"}
	assert.Equal(t, "153.220.34.35:51202", pa.getRemoteAddr(r))

	// It should not skip untrusted value
	r.Header["X-Forwarded-For"] = []string{"10.0.0.1, 153.220.34.35, 10.0.0.2, 10.0.0.3"}
	assert.Equal(t, "153.220.34.35:51202", pa.getRemoteAddr(r))

	// It should not skip invalid value
	r.Header["X-Forwarded-For"] = []string{"10.0.0.1, 153.290.34.35, 10.0.0.2"}
	assert.Equal(t, "10.0.0.2:51202", pa.getRemoteAddr(r))
}

func TestGetRemoteAddrWithAllTrustedProxies(t *testing.T) {
	pa := ProxyAddr{}
	err := pa.Init(CIDRLoopback, CIDRUniqueLocal)
	assert.NoError(t, err)

	r := &http.Request{RemoteAddr: "127.0.0.1:51202", Header: http.Header{"": []string{}}}

	// It should return remote address directly if no header present
	assert.Equal(t, "127.0.0.1:51202", pa.getRemoteAddr(r))

	// It should return header value if present
	r.Header["X-Forwarded-For"] = []string{"10.0.0.1"}
	assert.Equal(t, "10.0.0.1:51202", pa.getRemoteAddr(r))

	// It should return furthest header value if present
	r.Header["X-Forwarded-For"] = []string{"10.0.0.1, 10.0.0.2, 10.0.0.3"}
	assert.Equal(t, "10.0.0.1:51202", pa.getRemoteAddr(r))

	// It should return furthest valid header value
	r.Header["X-Forwarded-For"] = []string{"10.0.0.1, 153.290.34.35, 10.0.0.2"}
	assert.Equal(t, "10.0.0.2:51202", pa.getRemoteAddr(r))
}

func TestGetRemoteAddrIPv6WithNoProxy(t *testing.T) {
	pa := ProxyAddr{}

	r := &http.Request{RemoteAddr: "[2001:1620:28::116]:51202"}

	assert.Equal(t, "[2001:1620:28::116]:51202", pa.getRemoteAddr(r))
}

func TestProxyAddrHTTPHandler(t *testing.T) {
	pa := &ProxyAddr{}
	err := pa.Init(CIDRLoopback)
	assert.NoError(t, err)

	req, err := http.NewRequest("GET", "/", nil)
	assert.NoError(t, err)
	req.RemoteAddr = "127.0.0.1:22345"
	req.Header["X-Forwarded-For"] = []string{"153.220.34.35"}

	rr := httptest.NewRecorder()
	handler := pa.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.RemoteAddr))
	}))
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "153.220.34.35:22345", rr.Body.String())
}

func TestProxyAddrNegroniMiddleware(t *testing.T) {
	pa := &ProxyAddr{}
	err := pa.Init(CIDRLoopback)
	assert.NoError(t, err)

	req, err := http.NewRequest("GET", "/", nil)
	assert.NoError(t, err)
	req.RemoteAddr = "127.0.0.1:22345"
	req.Header["X-Forwarded-For"] = []string{"153.220.34.35"}

	rr := httptest.NewRecorder()
	handler := negroni.New()
	handler.Use(pa)
	handler.UseHandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.RemoteAddr))
	})
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "153.220.34.35:22345", rr.Body.String())
}
