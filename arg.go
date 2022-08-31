package main

var args Arg

type Arg struct {
	TargetOption
	RequestOption
	ResponseOption
	DictOption
	SpeedOption
	ProxyOption
	Node     bool `arg:"-N,--node" help:"Start in node mode"`
	NodePort int  `arg:"--node-port" help:"Port number of node mode [default: Random]"`
	Version  bool `arg:"-V,--" help:"display version and exit"`
}
