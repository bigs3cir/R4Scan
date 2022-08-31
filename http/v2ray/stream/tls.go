package stream

type TLSSettings struct {
	ServerName                       string           `json:"serverName,omitempty" validate:"omitempty,fqdn" errMsg:"invalid tls serverName"`
	Alpn                             []string         `json:"alpn,omitempty" validate:"omitempty,dive,oneof='h2'|oneof='http/1.1'" errMsg:"invalid tls alpn"`
	AllowInsecure                    bool             `json:"allowInsecure,omitempty"`
	DisableSystemRoot                bool             `json:"disableSystemRoot,omitempty"`
	Certificates                     []TLSCertificate `json:"certificates,omitempty" validate:"required_if=DisableSystemRoot true,dive" errMsg:"invalid certificate setting"`
	PinnedPeerCertificateChainSha256 []string         `json:"pinnedPeerCertificateChainSha256,omitempty"`
	VerifyClientCertificate          bool             `json:"verifyClientCertificate,omitempty"`
}

type TLSCertificate struct {
	Usage           string   `json:"usage,omitempty" validate:"omitempty,oneof=encipherment verify issue verifyclient" errMsg:"invalid certificate usage"`
	CertificateFile string   `json:"certificateFile,omitempty"`
	Certificate     []string `json:"certificate,omitempty" validate:"omitempty,dive,min=1,max=64" errMsg:"invalid certificate format"`
	KeyFile         string   `json:"keyFile,omitempty"`
	Key             []string `json:"key,omitempty" validate:"omitempty,dive,min=1,max=64" errMsg:"invalid certificate key format"`
}
