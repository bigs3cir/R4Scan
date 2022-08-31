package stream

type WSSettings struct {
	Path                string            `json:"path,omitempty"`
	Headers             map[string]string `json:"headers,omitempty" validate:"omitempty,gt=0,dive,keys,required,endkeys,required" errMsg:"invalid ws headers"`
	MaxEarlyData        int               `json:"maxEarlyData,omitempty"`
	EarlyDataHeaderName string            `json:"earlyDataHeaderName,omitempty"`
}
