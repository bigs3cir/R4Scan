package http

import (
	"fmt"
	shadowSocksR "github.com/sun8911879/shadowsocksR"
	"github.com/sun8911879/shadowsocksR/obfs"
	"github.com/sun8911879/shadowsocksR/protocol"
	"github.com/sun8911879/shadowsocksR/ssr"
	"github.com/sun8911879/shadowsocksR/tools/socks"
	"github.com/valyala/fasthttp"
	"net"
	"net/url"
	"r4scan/util"
	"r4scan/validator"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ShadowSocksR struct {
	Server   string
	Port     int
	Cipher   string
	Password string
	Obfs     *ShadowSocksRObfs
	Protocol *ShadowSocksRProtocol
}

var ShadowSocksRCipherList = map[string]struct{}{
	"aes-128-cfb":      {},
	"aes-192-cfb":      {},
	"aes-256-cfb":      {},
	"aes-128-ctr":      {},
	"aes-192-ctr":      {},
	"aes-256-ctr":      {},
	"aes-128-ofb":      {},
	"aes-192-ofb":      {},
	"aes-256-ofb":      {},
	"camellia-128-cfb": {},
	"camellia-192-cfb": {},
	"camellia-256-cfb": {},
	"des-cfb":          {},
	"bf-cfb":           {},
	"cast5-cfb":        {},
	"rc4-md5":          {},
	"chacha20":         {},
	"chacha20-ietf":    {},
	"salsa20":          {},
	"idea-cfb":         {},
	"rc2-cfb":          {},
	"seed-cfb":         {},
}

var ShadowSocksRProtocolList = map[string]struct{}{
	"origin":           {},
	"verify_sha1":      {},
	"auth_sha1_v4":     {},
	"auth_aes128_md5":  {},
	"auth_aes128_sha1": {},
}

var ShadowSocksRObfsList = map[string]struct{}{
	"plain":              {},
	"http_simple":        {},
	"http_post":          {},
	"random_head":        {},
	"tls1.2_ticket_auth": {},
}

type ShadowSocksRObfs struct {
	Schema string
	Param  string
}

type ShadowSocksRProtocol struct {
	Schema string
	Param  string
}

func (proxy *Proxy) ShadowSocksRDialer(timeout time.Duration) fasthttp.DialFunc {

	return func(addr string) (net.Conn, error) {

		var (
			cipher  *shadowSocksR.StreamCipher
			ssrConn *shadowSocksR.SSTCPConn
			conn    net.Conn
			err     error
		)

		cipher, err = shadowSocksR.NewStreamCipher(proxy.ShadowSocksR.Cipher, proxy.ShadowSocksR.Password)
		if err != nil {
			return nil, fmt.Errorf("ssr: invalid cipher \"%s\"", proxy.ShadowSocksR.Cipher)
		}

		proxyAddr := net.JoinHostPort(proxy.ShadowSocksR.Server, strconv.Itoa(proxy.ShadowSocksR.Port))
		if timeout == 0 {
			conn, err = fasthttp.DialDualStack(proxyAddr)
		} else {
			conn, err = fasthttp.DialDualStackTimeout(proxyAddr, timeout)
		}

		if err != nil {
			return nil, err
		}

		ssrConn = shadowSocksR.NewSSTCPConn(conn, cipher)
		if ssrConn.Conn == nil || ssrConn.RemoteAddr() == nil {
			return nil, fmt.Errorf("ssr: invalid ssr connection")
		}

		ssrConn.IObfs = obfs.NewObfs(proxy.ShadowSocksR.Obfs.Schema)
		if ssrConn.IObfs == nil {
			return nil, fmt.Errorf("ssr: cannot create obfs")
		}

		ssrConn.IObfs.SetServerInfo(&ssr.ServerInfoForObfs{
			Host:   proxy.ShadowSocksR.Server,
			Port:   uint16(proxy.ShadowSocksR.Port),
			Param:  proxy.ShadowSocksR.Obfs.Param,
			TcpMss: 1460,
		})

		ssrConn.IProtocol = protocol.NewProtocol(proxy.ShadowSocksR.Protocol.Schema)
		if ssrConn.IProtocol == nil {
			return nil, fmt.Errorf("ssr: cannot create protocol")
		}

		ssrConn.IProtocol.SetServerInfo(&ssr.ServerInfoForObfs{
			Host:   proxy.ShadowSocksR.Server,
			Port:   uint16(proxy.ShadowSocksR.Port),
			Param:  proxy.ShadowSocksR.Protocol.Param,
			TcpMss: 1460,
		})

		ssrConn.IObfs.SetData(ssrConn.IObfs.GetData())
		ssrConn.IProtocol.SetData(ssrConn.IProtocol.GetData())

		rawAddr := socks.ParseAddr(addr)

		if _, err = ssrConn.Write(rawAddr); err != nil {
			return nil, err
		}

		return ssrConn, nil
	}

}

func newShadowSocksR(urls *url.URL, rawUrl string) (proxy *Proxy, err error) {

	var (
		server     string
		port       int
		protocol   string
		cipher     string
		obfs       string
		password   string
		obfsparam  string
		protoparam string
		noParam    bool
	)

	value, err := util.Base64URLDecode(rawUrl[6:])
	if err != nil {
		return nil, fmt.Errorf("parse error: %v", err)
	}

	queryIndex := strings.Index(value, "/?")
	if queryIndex < 0 {
		queryIndex = len(value)
		noParam = true
	}

	data := regexp.MustCompile(`^(.+):([^:]+):([^:]*):([^:]+):([^:]*):([^:]+)`).FindStringSubmatch(value[:queryIndex])
	if len(data) != 7 {
		return nil, fmt.Errorf("parse error: invalid format")
	}

	server = strings.ReplaceAll(data[1], "[", "")
	server = strings.ReplaceAll(server, "]", "")

	if err = validator.Var(server, "required,fqdn|ip"); err != nil {
		return nil, fmt.Errorf("parse error: %v", err)
	}

	port, err = strconv.Atoi(data[2])
	if err != nil {
		return nil, fmt.Errorf("parse error: invalid port")
	}

	if err := validator.Var(port, "required,min=1,max=65535"); err != nil {
		return nil, fmt.Errorf("parse error: invalid port")
	}

	protocol = strings.ToLower(data[3])
	if _, exist := ShadowSocksRProtocolList[protocol]; !exist {
		return nil, fmt.Errorf("parse error: invalid protocol \"%s\"", protocol)
	}

	cipher = strings.ToLower(data[4])
	if _, exist := ShadowSocksRCipherList[cipher]; !exist {
		return nil, fmt.Errorf("parse error: invalid cipher \"%s\"", cipher)
	}

	obfs = strings.ToLower(data[5])
	if _, exist := ShadowSocksRObfsList[obfs]; !exist {
		return nil, fmt.Errorf("parse error: invalid obfs \"%s\"", cipher)
	}

	password, err = util.Base64URLDecode(data[6])
	if err != nil {
		return nil, fmt.Errorf("parse error: invalid password")
	}

	if !noParam {
		params, err := url.ParseQuery(value[queryIndex+2:])
		if err != nil {
			return nil, fmt.Errorf("parse error: invalid params")
		}

		if params.Has("obfsparam") {
			if obfsparam, err = util.Base64URLDecode(params.Get("obfsparam")); err != nil {
				return nil, fmt.Errorf("parse error: invalid obfsparam")
			}
		}

		if params.Has("protoparam") {
			if protoparam, err = util.Base64URLDecode(params.Get("protoparam")); err != nil {
				return nil, fmt.Errorf("parse error: invalid protoparam")
			}
		}
	}

	proxy = &Proxy{
		Server: server,
		Port:   port,
		Schema: "SSR",
		Url:    urls,
		ShadowSocksR: ShadowSocksR{
			Server:   server,
			Port:     port,
			Cipher:   cipher,
			Password: password,
			Obfs: &ShadowSocksRObfs{
				Schema: obfs,
				Param:  obfsparam,
			},
			Protocol: &ShadowSocksRProtocol{
				Schema: protocol,
				Param:  protoparam,
			},
		},
	}

	return
}
