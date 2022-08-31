package http

import (
	_ "encoding/json"
	"fmt"
	"github.com/valyala/fasthttp"
	"io"
	"net"
	"strconv"
	"time"
)

func socks5Reply(code byte) string {
	switch code {
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "unknown code: " + strconv.Itoa(int(code))
	}
}

func socks4Reply(code byte) string {
	switch code {
	case 0x5B:
		return "request rejected or failed"
	case 0x5C:
		return "identd error 0x5C"
	case 0x5D:
		return "identd error 0x5D"
	default:
		return "unknown code: " + strconv.Itoa(int(code))
	}
}

func (proxy *Proxy) SocksDialer(timeout time.Duration) fasthttp.DialFunc {

	switch proxy.Schema {
	case "SOCKS4", "SOCKS4A":
		return proxy.socks4Dialer(timeout)
	default:
		return proxy.socks5Dialer(timeout)
	}
}

func (proxy *Proxy) socks4Dialer(timeout time.Duration) fasthttp.DialFunc {

	return func(addr string) (net.Conn, error) {

		var (
			host string
			port int
			portStr string
			conn net.Conn
			err error
		)

		host, portStr, err = net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		port, _ = strconv.Atoi(portStr)
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port number error: %d", port)
		}

		//parse ip addr
		ip := net.ParseIP(host)

		//socks4 protocol does not support ipv6
		if ip != nil && ip.To16() != nil{
			return nil, fmt.Errorf("socks4 protocol does not support ipv6")
		}

		//socks4 protocol needs to use ip
		if ip == nil && proxy.Schema == "SOCKS4" {
			if ipaddr, err := net.ResolveIPAddr("ip4", host); err != nil {
				return nil, err
			} else {
				ip = ipaddr.IP
			}
		}

		//new connect
		proxyAddr := net.JoinHostPort(proxy.Server, strconv.Itoa(proxy.Port))
		if timeout == 0 {
			conn, err = fasthttp.DialDualStack(proxyAddr)
		} else {
			conn, err = fasthttp.DialDualStackTimeout(proxyAddr, timeout)
		}

		if err != nil {
			return nil, err
		}

		//new buf
		buf := make([]byte, 0, len(host) + 6)

		//VER: 4, CMD: 0x01 (CONNECT)
		buf = append(buf, 0x04, 0x01)

		//DSTPORT
		buf = append(buf, byte(port >> 8), byte(port))

		if proxy.Schema == "SOCKS4" || ip != nil {
			//socks4(fqdn), socks4(ip), socks4a(ip)

			//DSTIP
			buf = append(buf, ip.To4()...)
			//NULL
			buf = append(buf, 0x00)
		} else {
			//socks4a(fqdn)

			//DSTIP: 0x00 0x00 0x00 0x01
			buf = append(buf, 0x00, 0x00, 0x00, 0x01)
			//NULL
			buf = append(buf, 0x00)
			//FQDN
			buf = append(buf, host...)
			//NULL
			buf = append(buf, 0x00)
		}

		if _, err = conn.Write(buf); err != nil {
			return nil, err
		}

		//read VN, REP
		if _, err = io.ReadFull(conn, buf[:2]); err != nil {
			return nil, err
		}

		//check VN
		if buf[0] != 0x00 {
			return nil, fmt.Errorf("invalid protocol version: %d", buf[0])
		}

		//check REP
		if buf[1] != 0x5A {
			return nil, fmt.Errorf(socks4Reply(buf[1]))
		}

		//read DSTPORT, DSTIP
		if _, err = io.ReadFull(conn, buf[:6]); err != nil {
			return nil, err
		}

		return conn, nil

	}

}

func (proxy *Proxy) socks5Dialer(timeout time.Duration) fasthttp.DialFunc {

	return func(addr string) (net.Conn, error) {

		var (
			host string
			port int
			portStr string
			conn net.Conn
			err error
		)

		host, portStr, err = net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		port, _ = strconv.Atoi(portStr)
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port number error: %d", port)
		}

		//new connect
		proxyAddr := net.JoinHostPort(proxy.Server, strconv.Itoa(proxy.Port))
		if timeout == 0 {
			conn, err = fasthttp.DialDualStack(proxyAddr)
		} else {
			conn, err = fasthttp.DialDualStackTimeout(proxyAddr, timeout)
		}

		if err != nil {
			return nil, err
		}

		//new buf
		buf := make([]byte, 0, len(host) + 6)

		//VER 5
		buf = append(buf, 0x05)

		if !proxy.Auth {
			//NMETHODS: 1, METHODS: 0x00 (no authentication required)
			buf = append(buf, 0x01, 0x00)
		} else {
			//NMETHODS: 2, METHODS: 0x00, 0x02 (no authentication or username/password)
			buf = append(buf, 0x02, 0x00, 0x02)
		}

		if _, err = conn.Write(buf); err != nil {
			return nil, err
		}

		if _, err = io.ReadFull(conn, buf[:2]); err != nil {
			return nil, err
		}

		//check socks version
		if buf[0] != 0x05 {
			return nil, fmt.Errorf("invalid protocol version: %d", buf[0])
		}

		//authentication methods error
		if buf[1] == 0xFF {
			return nil, fmt.Errorf("no acceptable authentication methods")
		}

		if proxy.Auth && buf[1] != 0x00 {

			if len(proxy.User) == 0 || len(proxy.User) > 255 || len(proxy.Pass) == 0 || len(proxy.User) > 255 {
				return nil, fmt.Errorf("invalid username/password")
			}

			//reset buf
			buf = buf[:0]

			//password protocol version
			buf = append(buf, 0x01)

			//write username length & var
			buf = append(buf, byte(len(proxy.User)))
			buf = append(buf, proxy.User...)

			//write password length & var
			buf = append(buf, byte(len(proxy.Pass)))
			buf = append(buf, proxy.Pass...)

			if _, err = conn.Write(buf); err != nil {
				return nil, err
			}

			if _, err = io.ReadFull(conn, buf[:2]); err != nil {
				return nil, err
			}

			if buf[0] != 0x01 {
				return nil, fmt.Errorf("invalid username/password version")
			}

			if buf[1] != 0x00 {
				return nil, fmt.Errorf("username/password authentication failed")
			}

		}

		//reset buf
		buf = buf[:0]

		//CMD: 0x01 (CONNECT)
		buf = append(buf, 0x05, 0x01, 0)

		if ip := net.ParseIP(host); ip != nil {
			if ipv4 := ip.To4(); ipv4 != nil {
				//IPv4
				buf = append(buf, 0x01)
				buf = append(buf, ipv4...)
			} else if ipv6 := ip.To16(); ipv6 != nil {
				//IPv6
				buf = append(buf, 0x04)
				buf = append(buf, ipv6...)
			} else {
				return nil, fmt.Errorf("unknown address type: %s", host)
			}
		} else {
			if len(host) > 255 {
				return nil, fmt.Errorf("FQDN too long")
			}
			//FQDN
			buf = append(buf, 0x03)
			buf = append(buf, byte(len(host)))
			buf = append(buf, host...)
		}

		//PORT
		buf = append(buf, byte(port >> 8), byte(port))

		if _, err = conn.Write(buf); err != nil {
			return nil, err
		}

		if _, err = io.ReadFull(conn, buf[:4]); err != nil {
			return nil, err
		}

		//check socks version
		if buf[0] != 0x05 {
			return nil, fmt.Errorf("invalid protocol version(receive): %d", buf[0])
		}

		//check REP
		if buf[1] != 0x00 {
			return nil, fmt.Errorf(socks5Reply(buf[1]))
		}

		//check RSV
		if buf[2] != 0x00 {
			return nil, fmt.Errorf("non-zero reserved field")
		}

		//bytes to discard (port=2byte)
		bytesDiscard := 2

		//check ATYP
		switch buf[3] {
		case 0x01:
			bytesDiscard += net.IPv4len
		case 0x04:
			bytesDiscard += net.IPv6len
		case 0x03:
			if _, err = io.ReadFull(conn, buf[:1]); err != nil {
				return nil, fmt.Errorf("failed to read domain length: %s", host)
			}
			bytesDiscard += int(buf[0])
		default:
			return nil, fmt.Errorf("unknown address type(receive): %d", buf[3])
		}

		if cap(buf) < bytesDiscard {
			buf = make([]byte, bytesDiscard)
		} else {
			buf = buf[:bytesDiscard]
		}

		if _, err = io.ReadFull(conn, buf); err != nil {
			return nil, err
		}

		return conn, nil

	}

}