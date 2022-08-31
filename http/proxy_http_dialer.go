package http

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"github.com/valyala/fasthttp"
	"net"
	"strconv"
	"time"
)

func (proxy *Proxy) HTTPDialer(timeout time.Duration) fasthttp.DialFunc {

	return func(addr string) (net.Conn, error) {

		var (
			request  string
			response *fasthttp.Response
			conn     net.Conn
			err      error
		)

		proxyAddr := net.JoinHostPort(proxy.Server, strconv.Itoa(proxy.Port))

		if timeout == 0 {
			conn, err = fasthttp.DialDualStack(proxyAddr)
		} else {
			conn, err = fasthttp.DialDualStackTimeout(proxyAddr, timeout)
		}

		if err != nil {
			return nil, err
		}

		request = fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
		if proxy.Auth {
			auth := base64.StdEncoding.EncodeToString([]byte(proxy.User + ":" + proxy.Pass))
			request += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
		}
		request += "\r\n"

		if _, err = conn.Write([]byte(request)); err != nil {
			return nil, err
		}

		response = fasthttp.AcquireResponse()
		defer fasthttp.ReleaseResponse(response)

		response.SkipBody = true

		if err = response.Read(bufio.NewReader(conn)); err != nil {
			conn.Close()
			return nil, err
		}

		if response.StatusCode() != 200 {
			conn.Close()
			return nil, fmt.Errorf("could not connect to proxy: %s", proxy.String())
		}

		return conn, nil
	}
}
