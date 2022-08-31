package stream

type TCPSettings struct {
	TCPHeader *TCPHeader `json:"header,omitempty"`
}

type TCPHeader struct {
	Type     string             `json:"type,omitempty" validate:"omitempty,oneof=none http" errMsg:"invalid tcp header type"`
	Request  *TCPHeaderRequest  `json:"request,omitempty" validate:"omitempty,excluded_unless=Type http" errMsg:"invalid tcp header request"`
	Response *TCPHeaderResponse `json:"response,omitempty" validate:"omitempty,excluded_unless=Type http" errMsg:"invalid tcp header response"`
}

type TCPHeaderRequest struct {
	Version string              `json:"version,omitempty" validate:"omitempty,oneof='1.1' '2'" errMsg:"tcp header request: invalid http version"`
	Method  string              `json:"method,omitempty" validate:"omitempty,oneof=GET POST HEAD PUT PATCH OPTIONS DELETE" errMsg:"tcp header request: invalid http method"`
	Path    []string            `json:"path,omitempty" validate:"omitempty,gt=0,dive,required" errMsg:"tcp header request: invalid path"`
	Headers map[string][]string `json:"headers,omitempty"`
}

type TCPHeaderResponse struct {
	Version string              `json:"version,omitempty" validate:"omitempty,oneof='1.1' '2'" errMsg:"tcp header response: invalid http version"`
	Status  string              `json:"status,omitempty" validate:"omitempty,httpStatusCode" errMsg:"tcp header response: invalid http status"`
	Reason  string              `json:"reason,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
}
