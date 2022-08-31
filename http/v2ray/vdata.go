package v2ray

import (
	"encoding/json"
	"r4scan/http/v2ray/stream"
)

var VMessCipherList = map[string]struct{}{
	"auto":              {},
	"none":              {},
	"aes-128-gcm":       {},
	"chacha20-poly1305": {},
	"zero":              {},
}

type OutBounds struct {
	SendThrough    string          `json:"sendThrough,omitempty" validate:"omitempty,ip" errMsg:"invalid sendThrough"`
	Protocol       string          `json:"protocol" validate:"required,oneof=vmess vless trojan" errMsg:"invalid protocol"`
	Settings       json.RawMessage `json:"settings" validate:"required" errMsg:"invalid protocol setting"`
	StreamSettings *StreamSettings `json:"streamSettings,omitempty"`
	Mux            *MuxSettings    `json:"mux,omitempty"`
}

//VLessSettings  *protocol.VLessSettings  `json:"settings,omitempty" validate:"required_if=Protocol vless" errMsg:"invalid vless setting"`
//TrojanSettings *protocol.TrojanSettings `json:"settings,omitempty" validate:"required_if=Protocol trojan" errMsg:"invalid trojan setting"`
//VMessSettings  *protocol.VMessSettings  `json:"settings,omitempty" validate:"required_if=Protocol vmess" errMsg:"invalid vmess setting"`

type StreamSettings struct {
	Network      string               `json:"network,omitempty" validate:"omitempty,oneof=tcp kcp ws http quic" errMsg:"invalid stream network"`
	Security     string               `json:"security,omitempty" validate:"omitempty,oneof=none tls" errMsg:"invalid stream security"`
	TLSSettings  *stream.TLSSettings  `json:"tlsSettings,omitempty" validate:"omitempty,excluded_unless=Security tls" errMsg:"invalid stream tlsSettings"`
	TCPSettings  *stream.TCPSettings  `json:"tcpSettings,omitempty" validate:"omitempty,excluded_unless=Network tcp|required_without_all=Network" errMsg:"invalid stream tcpSettings"`
	KCPSettings  *stream.KCPSettings  `json:"kcpSettings,omitempty" validate:"omitempty,excluded_unless=Network kcp" errMsg:"invalid stream kcpSettings"`
	WSSettings   *stream.WSSettings   `json:"wsSettings,omitempty" validate:"omitempty,excluded_unless=Network ws" errMsg:"invalid stream wsSettings"`
	HTTPSettings *stream.HTTPSettings `json:"httpSettings,omitempty" validate:"omitempty,excluded_unless=Network http" errMsg:"invalid stream httpSettings"`
	QUICSettings *stream.HTTPSettings `json:"quicSettings,omitempty" validate:"omitempty,excluded_unless=Network quic" errMsg:"invalid stream quicSettings"`
}

type MuxSettings struct {
	Enable      bool `json:"enable,omitempty"`
	Concurrency int  `json:"concurrency,omitempty" validate:"omitempty,min=-1,max=1024" errMsg:"invalid mux concurrency"`
}
