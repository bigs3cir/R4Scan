package http

import (
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/valyala/fasthttp"
	"net/url"
	"r4scan/http/v2ray"
	"strconv"
	"strings"
	"time"
)

type Proxy struct {
	Server       string `validate:"required,fqdn|ip4_addr"`
	Port         int    `validate:"required,min=1,max=65535"`
	Schema       string `validate:"required"`
	User         string
	Pass         string
	Auth         bool
	Url          *url.URL
	ShadowSocks  ShadowSocks
	ShadowSocksR ShadowSocksR
	VMess        v2ray.OutBounds
	VLess        v2ray.OutBounds
	Trojan       v2ray.OutBounds
}

var SchemaList = map[string]struct{}{
	"HTTP":      {},
	"HTTPS":     {},
	"SOCKS4":    {},
	"SOCKS4A":   {},
	"SOCKS5":    {},
	"SOCKS5H":   {},
	"SS":        {},
	"SSR":       {},
	"VMESS":     {},
	"VLESS":     {},
	"TROJAN":    {},
	"TROJAN-GO": {},
}

func (proxy *Proxy) String() string {

	return proxy.Url.String()
}

func (proxy *Proxy) ConnectTest() (err error) {

	//check 204
	checkUrl := "http://www.gstatic.com/generate_204"

	//new http client
	client := NewClient().
		SetProxy(proxy).
		SetRetry(1).
		SetTimeout(time.Second * 5).
		SetMethod("HEAD")

	resp, err := client.Do(checkUrl)

	defer ReleaseResponse(resp)

	if err != nil {
		return err
	}

	if resp.StatusCode() != 204 {
		return fmt.Errorf("invalid status code: %d", resp.StatusCode())
	}

	return
}

func (proxy *Proxy) Dialer(timeout time.Duration) fasthttp.DialFunc {

	switch proxy.Schema {
	case "HTTP", "HTTPS":
		return proxy.HTTPDialer(timeout)
	case "SOCKS5", "SOCKS5H", "SOCKS4", "SOCKS4A":
		return proxy.SocksDialer(timeout)
	case "SS":
		return proxy.ShadowSocksDialer(timeout)
	case "SSR":
		return proxy.ShadowSocksRDialer(timeout)
	case "VMESS":
		return proxy.VMessDialer(timeout)
	case "VLESS":
		return proxy.VLessDialer(timeout)
	case "TROJAN", "TROJAN-GO":
		return proxy.TrojanDialer(timeout)
	default:
		return nil
	}
}

func NewProxy(rawUrl string) (proxy *Proxy, err error) {

	//validate
	var validate = validator.New()

	//parse url
	urls, err := url.Parse(rawUrl)
	if err != nil {
		fmt.Println(err)
		return
	}

	//verify schema
	schema := strings.ToUpper(urls.Scheme)

	if _, exist := SchemaList[schema]; !exist {
		return proxy, errors.New("invalid schema")
	}

	switch schema {
	case "SS":
		return newShadowSocks(urls, rawUrl)
	case "SSR":
		return newShadowSocksR(urls, rawUrl)
	case "VMESS":
		return newVMess(urls, rawUrl)
	case "VLESS":
		return newVLess(urls)
	case "TROJAN":
		return newTrojan(urls)
	}

	//verify server
	server := strings.ReplaceAll(urls.Hostname(), "[", "")
	server = strings.ReplaceAll(server, "]", "")

	err = validate.Var(server, "required,fqdn|ip")
	if err != nil {
		return
	}

	//get port
	port, err := strconv.Atoi(urls.Port())
	if err != nil {
		return
	}

	//verify port
	err = validate.Var(port, "required,min=1,max=65535")
	if err != nil {
		return
	}

	//get auth
	auth := urls.User != nil
	username := urls.User.Username()
	password, _ := urls.User.Password()

	proxy = &Proxy{
		Server: server,
		Port:   port,
		Schema: schema,
		User:   username,
		Pass:   password,
		Auth:   auth,
		Url:    urls,
	}

	return
}
