package http

import (
	"encoding/json"
	"fmt"
	"net/url"
	vdata "r4scan/http/v2ray"
	"r4scan/http/v2ray/protocol"
	"r4scan/http/v2ray/stream"
	"r4scan/util"
	"r4scan/validator"
	"strconv"
	"strings"
)

func newVLess(urls *url.URL, rawUrl string) (proxy *Proxy, err error) {

	var (
		alterId int
		port    int
	)

	link, err := util.ParseVmess(rawUrl)
	if err != nil {
		return nil, fmt.Errorf("parse error: invalid vmess url")
	}

	outBounds := vdata.OutBounds{}
	outBounds.Protocol = "vmess"

	streamSetting := &vdata.StreamSettings{}
	streamSetting.Network = link.Net

	switch strings.ToLower(link.Net) {
	case "tcp":
		streamSetting.TCPSettings = &stream.TCPSettings{}
		if link.Type == "http" {
			streamSetting.TCPSettings.TCPHeader = &stream.TCPHeader{}
			streamSetting.TCPSettings.TCPHeader.Type = "http"

			if link.Path != "" || link.Host != "" {
				streamSetting.TCPSettings.TCPHeader.Request = &stream.TCPHeaderRequest{}
			}

			path, host := strings.Split(link.Path, ","), strings.Split(link.Host, ",")
			if len(path) > 0 {
				streamSetting.TCPSettings.TCPHeader.Request.Path = path
			}
			if len(host) > 0 {
				streamSetting.TCPSettings.TCPHeader.Request.Headers = map[string][]string{"Host": host}
			}
		}
	case "kcp":
		if link.Type != "" && link.Type != "none" {
			streamSetting.KCPSettings = &stream.KCPSettings{}
			streamSetting.KCPSettings.Header = &stream.KCPHeader{Type: link.Type}
		}
	case "ws":
		if link.Path != "" || link.Host != "" {
			streamSetting.WSSettings = &stream.WSSettings{}
			if link.Path != "" {
				streamSetting.WSSettings.Path = link.Path
			}
			if link.Host != "" {
				streamSetting.WSSettings.Headers = map[string]string{"Host": link.Host}
			}
		}
	case "h2", "http":
		streamSetting.HTTPSettings = &stream.HTTPSettings{}
		host := strings.Split(link.Host, ",")
		if len(host) < 1 {
			return nil, fmt.Errorf("parse error: invalid http/2 host")
		}
		streamSetting.HTTPSettings.Headers = map[string][]string{"Host": host}
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
