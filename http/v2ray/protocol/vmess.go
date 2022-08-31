package protocol

type VMessSettings struct {
	VMessVNext []VMessVNext `json:"vnext" validate:"required,dive"`
}

type VMessVNext struct {
	Address string       `json:"address" validate:"required,fqdn|ip" errMsg:"invalid vmess address"`
	Port    int          `json:"port" validate:"required,min=1,max=65535" errMsg:"invalid vmess port"`
	Users   []VMessUsers `json:"users" validate:"required,dive"`
}

type VMessUsers struct {
	ID          string `json:"id" validate:"required,uuid" errMsg:"invalid vmess id"`
	AlterId     int    `json:"alterId,omitempty" validate:"omitempty,min=0,max=65535" errMsg:"invalid vmess alterid"`
	Level       int    `json:"level,omitempty" validate:"omitempty,min=0" errMsg:"invalid vmess userLevel"`
	Security    string `json:"security" validate:"required,vmessCipher" errMsg:"invalid vmess security"`
	Experiments string `json:"experiments,omitempty" validate:"omitempty,vmessExperiments" errMsg:"invalid vmess experiments"`
}
