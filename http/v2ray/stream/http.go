package stream

type HTTPSettings struct {
	Host []string `json:"host" validate:"gt=0,dive,fqdn" errMsg:"invalid http/2 host"`
	Path string `json:"path,omitempty"`
	Method string `json:"method,omitempty" validate:"omitempty,oneof=GET POST HEAD PUT PATCH OPTIONS DELETE" errMsg:"invalid http/2 method"`
	Headers map[string][]string `json:"headers,omitempty"`
}
