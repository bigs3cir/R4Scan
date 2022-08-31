package stream

type KCPSettings struct {
	MTU              int        `json:"mtu,omitempty" validate:"omitempty,min=576,max=1460" errMsg:"invalid kcp mtu"`
	TTI              int        `json:"tti,omitempty" validate:"omitempty,min=10,max=100" errMsg:"invalid kcp tti"`
	UplinkCapacity   int        `json:"uplinkCapacity,omitempty" validate:"omitempty,min=0,max=10000" errMsg:"invalid kcp uplinkCapacity"`
	DownlinkCapacity int        `json:"downlinkCapacity,omitempty" validate:"omitempty,min=0,max=10000" errMsg:"invalid kcp downlinkCapacity"`
	Congestion       bool       `json:"congestion,omitempty"`
	ReadBufferSize   int        `json:"readBufferSize,omitempty" validate:"omitempty,min=0,max=100" errMsg:"invalid kcp readBufferSize"`
	WriteBufferSize  int        `json:"writeBufferSize,omitempty" validate:"omitempty,min=0,max=100" errMsg:"invalid kcp writeBufferSize"`
	Header           *KCPHeader `json:"header,omitempty"`
	Seed             string     `json:"seed,omitempty"`
}

type KCPHeader struct {
	Type string `json:"type,omitempty" validate:"omitempty,oneof=none srtp utp wechat-video dtls wireguard" errMsg:"invalid kcp header type"`
}
