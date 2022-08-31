package stream

type QUICSettings struct {
	Security string      `json:"security,omitempty" validate:"omitempty,oneof=none aes-128-gcm chacha20-poly1305" errMsg:"invalid quic security"`
	Key      string      `json:"key,omitempty"`
	Header   *QUICHeader `json:"header,omitempty"`
}

type QUICHeader struct {
	Type string `json:"type,omitempty" validate:"omitempty,oneof=none srtp utp wechat-video dtls wireguard" errMsg:"invalid quic header type"`
}
