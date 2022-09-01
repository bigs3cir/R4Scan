package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/v2fly/v2ray-core/v4/app/log"
	"github.com/v2fly/v2ray-core/v4/common/serial"
	"github.com/valyala/fasthttp"
	"net"
	"net/url"
	"r4scan/http/v2ray/protocol"
	"r4scan/http/v2ray/stream"
	"r4scan/validator"
	"strconv"
	"strings"
	"time"

	v2ray "github.com/v2fly/v2ray-core/v4"
	_ "github.com/v2fly/v2ray-core/v4/app/proxyman/inbound"
	_ "github.com/v2fly/v2ray-core/v4/app/proxyman/outbound"
	vnet "github.com/v2fly/v2ray-core/v4/common/net"
	conf "github.com/v2fly/v2ray-core/v4/infra/conf/serial"
	vdata "r4scan/http/v2ray"
)

func (proxy *Proxy) VLessDialer(timeout time.Duration) fasthttp.DialFunc {

	var (
		config *v2ray.Config
	)

	configRaw, _ := json.MarshalIndent(map[string][]interface{}{
		"outbounds": {
			proxy.VLess,
		},
	}, "", "  ")

	configConf, err := conf.DecodeJSONConfig(bytes.NewReader(configRaw))
	if err != nil {
		return func(addr string) (net.Conn, error) {
			return nil, err
		}
	}

	config, err = configConf.Build()
	if err != nil {
		return func(addr string) (net.Conn, error) {
			return nil, err
		}
	}

	for i, v := range config.App {
		if v.Type == "v2ray.core.app.log.Config" {
			config.App[i] = serial.ToTypedMessage(&log.Config{
				ErrorLogType: 0,
			})
			break
		}
	}

	return func(addr string) (net.Conn, error) {

		var (
			host    string
			port    int
			portStr string
			conn    net.Conn
			err     error
		)

		host, portStr, err = net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		port, _ = strconv.Atoi(portStr)
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port number error: %d", port)
		}

		server, err := v2ray.New(config)
		if err != nil {
			return nil, err
		}

		dest := vnet.TCPDestination(vnet.ParseAddress(host), vnet.Port(port))
		ctx, cancel := context.WithCancel(context.Background())

		if timeout <= 0 {
			timeout = time.Second * 5
		}

		go func() {
			time.Sleep(timeout)
			cancel()
		}()

		conn, err = v2ray.Dial(ctx, server, dest)
		if err != nil {
			return nil, err
		}

		return conn, nil
	}

}

func newVLess(urls *url.URL) (proxy *Proxy, err error) {

	var (
		port       int
		types      string
		security   string
		host       []string
		path       string
		headerType string
	)

	port, err = strconv.Atoi(urls.Port())
	if err != nil {
		return nil, fmt.Errorf("parse error: invalid port")
	}

	vlessUser := protocol.VLessUsers{
		ID:         urls.User.String(),
		Encryption: "none",
	}

	if err = validator.Validator(vlessUser); err != nil {
		return nil, err
	}

	if types = strings.ToLower(urls.Query().Get("type")); types == "" {
		types = "tcp"
	}

	if security = strings.ToLower(urls.Query().Get("security")); security == "" {
		types = "none"
	}

	if hosts := strings.TrimSpace(urls.Query().Get("host")); hosts != "" {
		if strings.Contains(hosts, ",") {
			for _, v := range strings.Split(hosts, ",") {
				if v = strings.TrimSpace(v); v != "" {
					host = append(host, v)
				}
			}
		} else {
			host = append(host, hosts)
		}
	}

	if headerType = strings.TrimSpace(urls.Query().Get("headerType")); headerType == "" {
		headerType = "none"
	}

	path = strings.TrimSpace(urls.Query().Get("path"))

	outBounds := vdata.OutBounds{}
	outBounds.Protocol = "vless"

	streamSetting := &vdata.StreamSettings{}
	streamSetting.Network = types

	switch types {
	case "tcp":
		streamSetting.TCPSettings = &stream.TCPSettings{}
		if headerType == "http" {
			streamSetting.TCPSettings.TCPHeader = &stream.TCPHeader{}
			streamSetting.TCPSettings.TCPHeader.Type = "http"
			streamSetting.TCPSettings.TCPHeader.Request = &stream.TCPHeaderRequest{}
			if len(host) > 0 {
				streamSetting.TCPSettings.TCPHeader.Request.Headers = map[string][]string{"Host": host}
			}
			if path != "" {
				streamSetting.TCPSettings.TCPHeader.Request.Path = []string{path}
			}
		}
	case "kcp":
		streamSetting.KCPSettings = &stream.KCPSettings{}
		streamSetting.KCPSettings.Header = &stream.KCPHeader{Type: headerType}
		if seed := strings.TrimSpace(urls.Query().Get("seed")); seed != "" {
			streamSetting.KCPSettings.Seed = seed
		}
	case "ws":
		streamSetting.WSSettings = &stream.WSSettings{}
		if len(host) > 0 {
			streamSetting.WSSettings.Headers = map[string]string{"Host": host[0]}
		}
		if path != "" {
			streamSetting.WSSettings.Path = path
		}
	case "http":
		streamSetting.HTTPSettings = &stream.HTTPSettings{}
		if len(host) < 1 {
			streamSetting.HTTPSettings.Host = []string{urls.Hostname()}
		} else {
			streamSetting.HTTPSettings.Host = host
		}
		if path != "" {
			streamSetting.HTTPSettings.Path = path
		}
	case "quic":
		streamSetting.QUICSettings = &stream.QUICSettings{}
		if quicSecurity := strings.TrimSpace(urls.Query().Get("quicSecurity")); quicSecurity != "" {
			streamSetting.QUICSettings.Security = quicSecurity
		} else {
			streamSetting.QUICSettings.Security = "none"
		}
		if key := urls.Query().Get("key"); key == "" {
			if streamSetting.QUICSettings.Security != "none" {
				return nil, fmt.Errorf("parse error: invalid quic key")
			}
		} else {
			if streamSetting.QUICSettings.Security != "none" {
				streamSetting.QUICSettings.Key = key
			}
		}
		streamSetting.QUICSettings.Header = &stream.QUICHeader{Type: headerType}
	default:
		return nil, fmt.Errorf("parse error: invalid stream Type \"%s\"", types)
	}

	switch security {
	case "tls":
		streamSetting.Security = "tls"
		streamSetting.TLSSettings = &stream.TLSSettings{}
		if sni := urls.Query().Get("sni"); sni != "" {
			streamSetting.TLSSettings.ServerName = sni
		} else {
			streamSetting.TLSSettings.ServerName = urls.Hostname()
		}
		if urls.Query().Get("allowInsecure") == "1" {
			streamSetting.TLSSettings.AllowInsecure = true
		}
		streamSetting.TLSSettings.AllowInsecure = true
	case "none":
	default:
		return nil, fmt.Errorf("parse error: invalid security Type \"%s\"", security)
	}

	vlessVNext := protocol.VLessVNext{}
	vlessVNext.Address = urls.Hostname()
	vlessVNext.Port = port
	vlessVNext.Users = []protocol.VLessUsers{}
	vlessVNext.Users = append(vlessVNext.Users, vlessUser)

	vlessSettings := &protocol.VLessSettings{
		VLessVNext: []protocol.VLessVNext{
			vlessVNext,
		},
	}

	if err = validator.Validator(vlessSettings); err != nil {
		return nil, err
	}

	outBounds.StreamSettings = streamSetting
	if outBounds.Settings, err = json.Marshal(vlessSettings); err != nil {
		return nil, err
	}

	if err = validator.Validator(outBounds); err != nil {
		return nil, err
	}

	vv, _ := json.Marshal(outBounds)
	fmt.Println(string(vv))

	proxy = &Proxy{
		Server: urls.Hostname(),
		Port:   port,
		Schema: "VLESS",
		Url:    urls,
		VLess:  outBounds,
	}

	return
}
