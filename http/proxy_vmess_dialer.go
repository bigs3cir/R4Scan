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
	"r4scan/util"
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

func (proxy *Proxy) VMessDialer(timeout time.Duration) fasthttp.DialFunc {

	var (
		config *v2ray.Config
	)

	configRaw, _ := json.MarshalIndent(map[string][]interface{}{
		"outbounds": {
			proxy.VMess,
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

func newVMess(urls *url.URL, rawUrl string) (proxy *Proxy, err error) {

	var (
		alterId int
		port    int
		host    []string
	)

	link, err := util.ParseVmess(rawUrl)
	if err != nil {
		return nil, fmt.Errorf("parse error: invalid vmess url")
	}

	outBounds := vdata.OutBounds{}
	outBounds.Protocol = "vmess"

	streamSetting := &vdata.StreamSettings{}
	streamSetting.Network = strings.ToLower(link.Net)

	if link.Host != "" {
		if strings.Contains(link.Host, ",") {
			for _, v := range strings.Split(link.Host, ",") {
				if v = strings.TrimSpace(v); v != "" {
					host = append(host, v)
				}
			}
		} else {
			host = append(host, link.Host)
		}
	}

	switch strings.ToLower(link.Net) {
	case "tcp":
		streamSetting.TCPSettings = &stream.TCPSettings{}
		if link.Type == "http" {
			streamSetting.TCPSettings.TCPHeader = &stream.TCPHeader{}
			streamSetting.TCPSettings.TCPHeader.Type = "http"
			streamSetting.TCPSettings.TCPHeader.Request = &stream.TCPHeaderRequest{}
			if len(host) > 0 {
				streamSetting.TCPSettings.TCPHeader.Request.Headers = map[string][]string{"Host": host}
			}
			if link.Path != "" {
				streamSetting.TCPSettings.TCPHeader.Request.Path = []string{link.Path}
			}
		}
	case "kcp":
		if link.Type != "" && link.Type != "none" {
			streamSetting.KCPSettings = &stream.KCPSettings{}
			streamSetting.KCPSettings.Header = &stream.KCPHeader{Type: link.Type}
		}
	case "ws":
		if len(host) > 0 || link.Path != "" {
			streamSetting.WSSettings = &stream.WSSettings{}
			if len(host) > 0 {
				streamSetting.WSSettings.Headers = map[string]string{"Host": host[0]}
			}
			if link.Path != "" {
				streamSetting.WSSettings.Path = link.Path
			}
		}
	case "h2", "http":
		streamSetting.HTTPSettings = &stream.HTTPSettings{}
		if len(host) < 1 {
			return nil, fmt.Errorf("parse error: invalid http/2 host")
		}
		streamSetting.HTTPSettings.Host = host
		streamSetting.HTTPSettings.Path = link.Path
	}

	if link.TLS == "tls" {
		streamSetting.Security = "tls"
		if link.Host != "" {
			streamSetting.TLSSettings = &stream.TLSSettings{}
			streamSetting.TLSSettings.ServerName = link.Host
		}
	}

	switch link.Aid.(type) {
	case string:
		alterId, _ = strconv.Atoi(link.Aid.(string))
	case int:
		alterId = link.Aid.(int)
	case int32:
		alterId = int(link.Aid.(int32))
	case int64:
		alterId = int(link.Aid.(int64))
	case float64:
		alterId = int(link.Aid.(float64))
	case float32:
		alterId = int(link.Aid.(float32))
	default:
		return nil, fmt.Errorf("parse error: invalid alterId \"%v\"", link.Aid)
	}

	switch link.Port.(type) {
	case string:
		port, _ = strconv.Atoi(link.Port.(string))
	case int:
		port = link.Port.(int)
	case int32:
		port = int(link.Port.(int32))
	case int64:
		port = int(link.Port.(int64))
	case float64:
		port = int(link.Port.(float64))
	case float32:
		port = int(link.Port.(float32))
	default:
		return nil, fmt.Errorf("parse error: invalid port \"%v\"", link.Port)
	}

	vmessUser := protocol.VMessUsers{}
	vmessUser.ID = link.ID
	vmessUser.AlterId = alterId
	vmessUser.Security = "auto"

	vmessVNext := protocol.VMessVNext{}
	vmessVNext.Address = link.Add
	vmessVNext.Port = port
	vmessVNext.Users = []protocol.VMessUsers{}
	vmessVNext.Users = append(vmessVNext.Users, vmessUser)

	vmessSettings := &protocol.VMessSettings{
		VMessVNext: []protocol.VMessVNext{
			vmessVNext,
		},
	}

	if err = validator.Validator(vmessSettings); err != nil {
		return nil, err
	}

	outBounds.StreamSettings = streamSetting
	if outBounds.Settings, err = json.Marshal(vmessSettings); err != nil {
		return nil, err
	}

	if err = validator.Validator(outBounds); err != nil {
		return nil, err
	}

	proxy = &Proxy{
		Server: link.Add,
		Port:   port,
		Schema: "VMESS",
		Url:    urls,
		VMess:  outBounds,
	}

	return
}
