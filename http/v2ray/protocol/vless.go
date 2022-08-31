package protocol

type VLessSettings struct {
	VLessVNext []VLessVNext `json:"vnext" validate:"required,dive"`
}

type VLessVNext struct {
	Address string       `json:"address" validate:"required,fqdn|ip" errMsg:"invalid vless address"`
	Port    int          `json:"port" validate:"required,min=1,max=65535" errMsg:"invalid vless port"`
	Users   []VLessUsers `json:"users" validate:"required,dive"`
}

type VLessUsers struct {
	ID         string `json:"id" validate:"required,uuid" errMsg:"invalid vless id"`
	Encryption string `json:"encryption" validate:"required,oneof=none" errMsg:"invalid vless encryption"`
	Level      int    `json:"level,omitempty" validate:"omitempty,min=0" errMsg:"invalid vless userLevel"`
}
