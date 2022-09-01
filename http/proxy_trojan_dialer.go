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

func (proxy *Proxy) TrojanDialer(timeout time.Duration) fasthttp.DialFunc {

	var (
		config *v2ray.Config
	)

	configRaw, _ := json.MarshalIndent(map[string][]interface{}{
		"outbounds": {
			proxy.Trojan,
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

func newTrojan(urls *url.URL) (proxy *Proxy, err error) {

	var (
		port          int
		sni           string
		allowInsecure bool
	)

	port, err = strconv.Atoi(urls.Port())
	if err != nil {
		return nil, fmt.Errorf("parse error: invalid port")
	}

	trojanUser := protocol.TrojanServers{
		Address:  urls.Hostname(),
		Port:     port,
		Password: urls.User.String(),
	}

	if err = validator.Validator(trojanUser); err != nil {
		return nil, err
	}

	if urls.Query().Has("peer") {
		sni = urls.Query().Get("peer")
	}

	if urls.Query().Has("sni") {
		sni = urls.Query().Get("sni")
	}

	if strings.TrimSpace(sni) == "" {
		sni = urls.Hostname()
	}

	if urls.Query().Has("allowInsecure") {
		allowInsecure = true
	}

	outBounds := vdata.OutBounds{}
	outBounds.Protocol = "trojan"

	streamSetting := &vdata.StreamSettings{}
	streamSetting.Network = "tcp"
	streamSetting.Security = "tls"

	streamSetting.TLSSettings = &stream.TLSSettings{}
	streamSetting.TLSSettings.ServerName = sni
	streamSetting.TLSSettings.AllowInsecure = allowInsecure

	trojanSettings := &protocol.TrojanSettings{
		TrojanServers: []protocol.TrojanServers{
			trojanUser,
		},
	}

	if err = validator.Validator(trojanSettings); err != nil {
		return nil, err
	}

	outBounds.StreamSettings = streamSetting
	if outBounds.Settings, err = json.Marshal(trojanSettings); err != nil {
		return nil, err
	}

	if err = validator.Validator(outBounds); err != nil {
		return nil, err
	}

	proxy = &Proxy{
		Server: urls.Hostname(),
		Port:   port,
		Schema: "TROJAN",
		Url:    urls,
		Trojan: outBounds,
	}

	return
}
