package main

type TargetOption struct {
	URL []string `arg:"-u,--url" help:"Target url" validate:"required,unique,dive,url" errMsg:"invalid URL"`
}

type SpeedOption struct {
	Thread   int `arg:"-t,--thread" default:"20" help:"Number of threads" validate:"omitempty,min=1,max=500" errMsg:"invalid thread (Limit range: 1-500)"`
	MaxSpeed int `arg:"--max-speed" default:"200" help:"Maximum number of requests per second" validate:"omitempty,min=1,max=10000" errMsg:"invalid maxSpeed (Limit range: 1-10000)"`
}

type RequestOption struct {
	Method        string            `default:"HEAD" help:"HTTP request method" validate:"omitempty,oneof=get GET post POST put PUT head HEAD delete DELETE options OPTIONS" errMsg:"invalid method"`
	Timeout       int               `default:"5000" help:"Effective response time of the request (ms)" validate:"omitempty,min=100,max=120000" errMsg:"invalid timeout (Limit range: 100-120000)"`
	Delay         int               `default:"0" help:"Limit the interval between each request (ms)" validate:"omitempty,min=0,max=120000" errMsg:"invalid delay (Limit range: 0-120000)"`
	Retry         int               `default:"1" help:"Number of retries after request failure" validate:"omitempty,min=0,max=5" errMsg:"invalid retries (Limit range: 0-5)"`
	UserAgent     string            `arg:"--user-agent" default:"Random" help:"User-Agent for each request" validate:"omitempty,min=1,max=100" errMsg:"invalid userAgent (String length limit range: 1-100)"`
	XForwardedFor string            `arg:"--xff" placeholder:"X-FORWARDED-FOR" help:"X-Forwarded-For for each request" validate:"omitempty,min=1,max=100" errMsg:"invalid xForwardedFor (String length limit range: 1-100)"`
	Header        map[string]string `help:"Custom requests header" validate:"omitempty,dive,keys,min=1,max=100,ne=host,ne=HOST,endkeys" errMsg:"invalid header (Example: key=value, \"key\"=\"value\")"`
	Body          string            `help:"Custom requests body" validate:"omitempty,excluded_unless=Method POST Method post Method PUT Method put,min=1,max=100" errMsg:"invalid body (String length limit range: 1-100)"`
}

type ProxyOption struct {
	Proxy     []string `help:"Sending requests using a proxy" validate:"omitempty,unique,dive,url" errMsg:"invalid proxy"`
	ProxyFile string   `arg:"--proxy-file" help:"Load proxy from file" validate:"omitempty,min=1,max=100" errMsg:"invalid proxyFile (String length limit range: 1-100)"`
	ProxyURL  []string `arg:"--proxy-url" help:"Load proxy from URL" validate:"omitempty,unique,dive,url" errMsg:"invalid proxyURL"`
}

type ResponseOption struct {
	Status   []string `help:"Valid HTTP status code [default: 200 301 302 401 403]" validate:"omitempty,unique,dive,httpStatusCode" errMsg:"invalid HTTP status code"`
	Ignore   []string `help:"Ignore these keywords from the response" validate:"omitempty,unique,dive,min=1,max=100" errMsg:"invalid ignore (String length limit range: 1-100)"`
	Required []string `help:"These keywords must be present in the response" validate:"omitempty,unique,dive,min=1,max=100" errMsg:"invalid required (String length limit range: 1-100)"`
}

type DictOption struct {
	Dict     []string          `arg:"-d,--dict" help:"Load the specified dictionary" validate:"omitempty,unique,dive,min=1,max=100" errMsg:"invalid dict (String length limit range: 1-100)"`
	DictPath string            `arg:"--dict-path" default:"dict" help:"Load dictionary from specified path" validate:"omitempty,min=1,max=100" errMsg:"invalid dictPath (String length limit range: 1-100)"`
	Ext      []string          `arg:"-x,--extension" help:"Set extension" validate:"omitempty,unique,dive,min=1,max=20" errMsg:"invalid ext (String length limit range: 1-20)"`
	Variable map[string]string `arg:"-v,--variable" help:"Custom Variable" validate:"omitempty,dive,keys,min=1,max=100,ne=ext,ne=EXT,endkeys,min=1" errMsg:"invalid variable (Example: key=value, \"key\"=\"value\")"`
}
