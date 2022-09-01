package util

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

//Original code from vmessping
//Minor modifications were made to accommodate more cases
//https://github.com/v2fly/vmessping

type VmessLink struct {
	Ver      string      `json:"-"`
	Add      string      `json:"add"`
	Aid      interface{} `json:"aid"`
	Host     string      `json:"host"`
	ID       string      `json:"id"`
	Net      string      `json:"net"`
	Path     string      `json:"path"`
	Port     interface{} `json:"port"`
	Ps       string      `json:"ps"`
	TLS      string      `json:"tls"`
	Type     string      `json:"type"`
	OrigLink string      `json:"-"`
}

func newQuanVmess(vmess string) (*VmessLink, error) {

	if !strings.HasPrefix(vmess, "vmess://") {
		return nil, fmt.Errorf("vmess unreconized: %s", vmess)
	}
	b64 := vmess[8:]
	b, err := Base64URLDecode(b64)
	if err != nil {
		return nil, err
	}

	info := b
	v := &VmessLink{}
	v.OrigLink = vmess
	v.Ver = "2"

	psn := strings.SplitN(info, " = ", 2)
	if len(psn) != 2 {
		return nil, fmt.Errorf("part error", info)
	}
	v.Ps = psn[0]
	params := strings.Split(psn[1], ",")
	v.Add = params[1]
	v.Port = params[2]
	v.ID = strings.ToLower(strings.Trim(params[4], "\""))
	v.Aid = "0"
	v.Net = "tcp"
	v.Type = "none"

	if len(params) > 4 {
		for _, pkv := range params[5:] {
			kvp := strings.SplitN(pkv, "=", 2)
			if kvp[0] == "over-tls" && kvp[1] == "true" {
				v.TLS = "tls"
			}

			if kvp[0] == "obfs" && kvp[1] == "ws" {
				v.Net = "ws"
			}

			if kvp[0] == "obfs" && kvp[1] == "http" {
				v.Type = "http"
			}

			if kvp[0] == "obfs-path" {
				v.Path = strings.Trim(kvp[1], "\"")
			}

			if kvp[0] == "obfs-header" {
				hd := strings.Trim(kvp[1], "\"")
				for _, hl := range strings.Split(hd, "[Rr][Nn]") {
					if strings.HasPrefix(hl, "Host:") {
						host := hl[5:]
						if host != v.Add {
							v.Host = host
						}
						break
					}
				}
			}

		}
	}

	return v, nil
}

func newVnVmess(vmess string) (*VmessLink, error) {

	if !strings.HasPrefix(vmess, "vmess://") {
		return nil, fmt.Errorf("vmess unreconized: %s", vmess)
	}

	b64 := vmess[8:]
	b, err := Base64URLDecode(b64)
	if err != nil {
		return nil, err
	}

	v := &VmessLink{}
	if err := json.Unmarshal([]byte(b), v); err != nil {
		return nil, err
	}
	v.ID = strings.ToLower(v.ID)
	v.OrigLink = vmess

	return v, nil
}

func newRkVmess(vmess string) (*VmessLink, error) {

	if !strings.HasPrefix(vmess, "vmess://") {
		return nil, fmt.Errorf("vmess unreconized: %s", vmess)
	}
	url, err := url.Parse(vmess)
	if err != nil {
		return nil, err
	}
	link := &VmessLink{}
	link.Ver = "2"
	link.OrigLink = vmess

	b64 := url.Host
	b, err := Base64URLDecode(b64)
	if err != nil {
		return nil, err
	}

	mhp := strings.SplitN(b, ":", 3)
	if len(mhp) != 3 {
		return nil, fmt.Errorf("vmess unreconized: method:host:port -- %v", mhp)
	}
	// mhp[0] is the encryption method
	link.Port = mhp[2]
	idadd := strings.SplitN(mhp[1], "@", 2)
	if len(idadd) != 2 {
		return nil, fmt.Errorf("vmess unreconized: id@addr -- %v", idadd)
	}
	link.ID = strings.ToLower(idadd[0])
	link.Add = idadd[1]
	link.Aid = "0"

	vals := url.Query()
	if v := vals.Get("remarks"); v != "" {
		link.Ps = v
	}
	if v := vals.Get("path"); v != "" {
		link.Path = v
	}
	if v := vals.Get("tls"); v == "1" {
		link.TLS = "tls"
	}
	if v := vals.Get("obfs"); v != "" {
		switch v {
		case "websocket":
			link.Net = "ws"
		case "none":
			link.Net = "tcp"
			link.Type = "none"
		}
	}
	if v := vals.Get("obfsParam"); v != "" {
		link.Host = v
	}

	return link, nil
}

func ParseVmess(vmess string) (*VmessLink, error) {
	var lk *VmessLink
	if o, nerr := newVnVmess(vmess); nerr == nil {
		lk = o
	} else if o, rerr := newRkVmess(vmess); rerr == nil {
		lk = o
	} else if o, qerr := newQuanVmess(vmess); qerr == nil {
		lk = o
	} else {
		return nil, fmt.Errorf("%v, %v, %v", nerr, rerr, qerr)
	}
	return lk, nil
}
