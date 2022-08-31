package protocol

type TrojanSettings struct {
	TrojanServers []TrojanServers `json:"servers" validate:"required,dive"`
}

type TrojanServers struct {
	Address  string `json:"address" validate:"required,fqdn|ip" errMsg:"invalid trojan address"`
	Port     int    `json:"port" validate:"required,min=1,max=65535" errMsg:"invalid trojan port"`
	Password string `json:"password" validate:"required" errMsg:"invalid trojan password"`
	Email    string `json:"email,omitempty" validate:"omitempty,email" errMsg:"invalid trojan userEmail"`
	Level    int    `json:"level,omitempty" validate:"omitempty,min=0" errMsg:"invalid trojan userLevel"`
}
