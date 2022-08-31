package http

import (
	"fmt"
	"github.com/Dreamacro/clash/transport/simple-obfs"
	shadowsocks2 "github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"github.com/valyala/fasthttp"
	"net"
	"net/url"
	"r4scan/util"
	"r4scan/validator"
	"strconv"
	"strings"
	"time"
)

type ShadowSocks struct {
	Server   string
	Port     int
	Cipher   string
	Password string
	Key      []byte
	Obfs     *ShadowSocksObfs
}

var ShadowSocksCipherList = map[string]struct{}{
	"aead_aes_128_gcm":       {},
	"aead_aes_256_gcm":       {},
	"aead_chacha20_poly1305": {},
	"aes-128-gcm":            {},
	"aes-256-gcm":            {},
	"aes-128-cfb":            {},
	"aes-192-cfb":            {},
	"aes-256-cfb":            {},
	"aes-128-ctr":            {},
	"aes-192-ctr":            {},
	"aes-256-ctr":            {},
	"des-cfb":                {},
	"bf-cfb":                 {},
	"cast5-cfb":              {},
	"rc4-md5":                {},
	"rc4-md5-6":              {},
	"chacha20":               {},
	"chacha20-ietf":          {},
	"chacha20-ietf-poly1305": {},
	"salsa20":                {},
}

type ShadowSocksObfs struct {
	Schema string
	Host   string
}

func (proxy *Proxy) ShadowSocksDialer(timeout time.Duration) fasthttp.DialFunc {

	return func(addr string) (net.Conn, error) {

		var (
			ssCipher  *shadowsocks.Cipher
			ss2Cipher shadowsocks2.Cipher
			conn      net.Conn
			err       error
		)

		ssCipher, _ = shadowsocks.NewCipher(proxy.ShadowSocks.Cipher, proxy.ShadowSocks.Password)
		if ssCipher == nil {
			ss2Cipher, _ = shadowsocks2.PickCipher(proxy.ShadowSocks.Cipher, proxy.ShadowSocks.Key, proxy.ShadowSocks.Password)
		}

		if ssCipher == nil && ss2Cipher == nil {
			return nil, fmt.Errorf("ss: invalid cipher \"%s\"", proxy.ShadowSocks.Cipher)
		}

		proxyAddr := net.JoinHostPort(proxy.ShadowSocks.Server, strconv.Itoa(proxy.ShadowSocks.Port))
		if timeout == 0 {
			conn, err = fasthttp.DialDualStack(proxyAddr)
		} else {
			conn, err = fasthttp.DialDualStackTimeout(proxyAddr, timeout)
		}

		if err != nil {
			return nil, err
		}

		if proxy.ShadowSocks.Obfs != nil {
			if proxy.ShadowSocks.Obfs.Schema == "http" {
				conn = obfs.NewHTTPObfs(conn, proxy.ShadowSocks.Obfs.Host, strconv.Itoa(proxy.ShadowSocks.Port))
			} else {
				conn = obfs.NewTLSObfs(conn, proxy.ShadowSocks.Obfs.Host)
			}
		}

		if ssCipher != nil {
			conn = shadowsocks.NewConn(conn, ssCipher.Copy())
		} else {
			conn = ss2Cipher.StreamConn(conn)
		}

		rawAddr, err := shadowsocks.RawAddr(addr)
		if err != nil {
			return nil, err
		}

		if _, err = conn.Write(rawAddr); err != nil {
			return nil, err
		}

		return conn, nil

	}

}

func newShadowSocks(urls *url.URL, rawUrl string) (proxy *Proxy, err error) {

	var (
		server   string
		port     int
		cipher   string
		password string
		key      []byte
		obfs     *ShadowSocksObfs
	)

	if errs := validator.Var(urls.Hostname(), "required,fqdn|ip"); errs != nil {

		//qrcode mode

		rawUrl = rawUrl[5:]

		tagIndex := strings.Index(rawUrl, "#")
		if tagIndex > -1 {
			rawUrl = rawUrl[:tagIndex]
		}

		value, err := util.Base64URLDecode(rawUrl)
		if err != nil {
			return nil, fmt.Errorf("parse error: %v", err)
		}

		splitIndex := strings.Index(value, "@")
		if splitIndex < 0 {
			return nil, fmt.Errorf("parse error: invalid format")
		}

		userInfo := value[:splitIndex]
		serverInfo := value[splitIndex+1:]

		userSplit := strings.Index(userInfo, ":")
		if userSplit < 0 {
			return nil, fmt.Errorf("parse error: invalid userInfo")
		}

		serverSplit := strings.Index(serverInfo, ":")
		if serverSplit < 0 {
			return nil, fmt.Errorf("parse error: invalid serverInfo")
		}

		cipher = strings.ToLower(userInfo[:userSplit])
		password = userInfo[userSplit+1:]

		if _, exist := ShadowSocksCipherList[cipher]; !exist {
			return nil, fmt.Errorf("parse error: invalid cipher \"%s\"", cipher)
		}

		server = strings.ReplaceAll(serverInfo[:serverSplit], "[", "")
		server = strings.ReplaceAll(server, "]", "")

		ports := serverInfo[serverSplit+1:]

		if err = validator.Var(server, "required,fqdn|ip"); err != nil {
			return nil, fmt.Errorf("parse error: %v", err)
		}

		if port, err = strconv.Atoi(ports); err != nil {
			return nil, fmt.Errorf("parse error: invalid port")
		}

		if err = validator.Var(port, "required,min=1,max=65535"); err != nil {
			return nil, fmt.Errorf("parse error: invalid port")
		}

	} else {

		//sip002 mode

		server = urls.Hostname()

		if urls.User.String() == "" {
			return nil, fmt.Errorf("parse error: invalid userInfo")
		}

		userInfo, err := util.Base64URLDecode(urls.User.String())
		if err != nil {
			return nil, fmt.Errorf("parse error: %v", err)
		}

		userSplit := strings.Index(userInfo, ":")
		if userSplit < 0 {
			return nil, fmt.Errorf("parse error: invalid userInfo")
		}

		cipher = strings.ToLower(userInfo[:userSplit])
		password = userInfo[userSplit+1:]

		if _, exist := ShadowSocksCipherList[cipher]; !exist {
			return nil, fmt.Errorf("parse error: invalid cipher \"%s\"", cipher)
		}

		port, err = strconv.Atoi(urls.Port())
		if err != nil {
			return nil, fmt.Errorf("parse error: invalid port")
		}

		if err := validator.Var(port, "required,min=1,max=65535"); err != nil {
			return nil, fmt.Errorf("parse error: invalid port")
		}

		queryRaw, err := url.QueryUnescape(urls.RawQuery)
		if err != nil {
			return nil, fmt.Errorf("parse error: invalid query")
		}

		queryRaw = strings.ReplaceAll(queryRaw, ";", "&")
		query, err := url.ParseQuery(queryRaw)
		if err != nil {
			return nil, fmt.Errorf("parse error: invalid params")
		}

		if query.Has("plugin") && query.Has("obfs") {

			plugin := strings.ToLower(query.Get("plugin"))
			obfsSchema := strings.ToLower(query.Get("obfs"))
			obfsHost := query.Get("obfs-host")

			if plugin != "obfs-local" && plugin != "simple-obfs" {
				return nil, fmt.Errorf("parse error: unknown plugin \"%s\"", plugin)
			}
			if obfsSchema != "http" && obfsSchema != "tls" {
				return nil, fmt.Errorf("parse error: unknown obfs schema \"%s\"", obfsSchema)
			}

			obfs = &ShadowSocksObfs{
				Schema: obfsSchema,
				Host:   obfsHost,
			}

		}
	}

	proxy = &Proxy{
		Server: server,
		Port:   port,
		Schema: "SS",
		Url:    urls,
		ShadowSocks: ShadowSocks{
			Server:   server,
			Port:     port,
			Cipher:   cipher,
			Password: password,
			Key:      key,
			Obfs:     obfs,
		},
	}

	return

}
