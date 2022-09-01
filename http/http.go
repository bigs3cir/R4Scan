package http

import (
	"crypto/tls"
	"fmt"
	"github.com/valyala/fasthttp"
	"r4scan/util"
	"strings"
	"sync"
	"time"
)

type Client struct {
	client  *fasthttp.Client
	method  string
	header  sync.Map
	body    string
	proxy   *Proxy
	retry   int
	timeout time.Duration
}

func NewClient() *Client {
	return &Client{
		method:  "GET",
		retry:   1,
		timeout: time.Second * 5,
		client: &fasthttp.Client{
			DialDualStack:                 true,
			MaxIdleConnDuration:           time.Hour,
			ReadTimeout:                   time.Second * 5,
			WriteTimeout:                  time.Second * 5,
			MaxResponseBodySize:           5242880,
			DisableHeaderNamesNormalizing: true,
			DisablePathNormalizing:        true,
			RetryIf: func(*fasthttp.Request) bool {
				return false
			},
		},
	}
}

func ReleaseResponse(response *fasthttp.Response) {

	fasthttp.ReleaseResponse(response)
}

func (c *Client) SetTimeout(time time.Duration) *Client {

	c.timeout = time
	return c
}

func (c *Client) SetMethod(method string) *Client {

	c.method = strings.ToUpper(method)
	return c
}

func (c *Client) SetHeader(header map[string]string) *Client {

	for key, value := range header {

		if strings.ToLower(key) == "user-agent" {
			key = "User-Agent"
			c.header.LoadOrStore(key, []string{value})
			continue
		}

		if strings.ToLower(key) == "x-forwarded-for" {
			key = "X-Forwarded-For"
			c.header.LoadOrStore(key, []string{value})
			continue
		}

		if values, exist := c.header.Load(key); !exist {
			c.header.Store(key, []string{value})
		} else {
			values = append(values.([]string), value)
			c.header.Store(key, values)
		}

	}

	return c
}

func (c *Client) SetUserAgent(userAgent string) *Client {

	c.SetHeader(map[string]string{
		"User-Agent": userAgent,
	})

	return c
}

func (c *Client) SetXForwardedFor(xForwardedFor string) *Client {

	c.SetHeader(map[string]string{
		"X-Forwarded-For": xForwardedFor,
	})

	return c
}

func (c *Client) SetBody(body string) *Client {

	c.body = body
	return c
}

func (c *Client) SetProxy(proxy *Proxy) *Client {

	c.client.Dial = proxy.Dialer(c.timeout)
	return c
}

func (c *Client) SetRetry(retry int) *Client {

	c.retry = retry
	return c
}

func (c *Client) SetCertificateVerify(skip bool) *Client {

	if skip {
		c.client.TLSConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}
	return c
}

func (c *Client) Do(url string) (response *fasthttp.Response, err error) {

	request := fasthttp.AcquireRequest()
	request.SetRequestURI(url)
	request.Header.SetMethod(c.method)

	switch c.method {
	case fasthttp.MethodPost, fasthttp.MethodPut:
		if strings.TrimSpace(c.body) != "" {
			request.SetBodyString(c.body)
		}
	}

	//build header
	c.buildHeader(request)

	response = fasthttp.AcquireResponse()

	for i := 0; i <= c.retry; i++ {
		fmt.Println(88888)
		if err = c.client.DoTimeout(request, response, c.timeout); err == nil {
			break
		}
	}

	fasthttp.ReleaseRequest(request)

	if err != nil {
		return
	}

	return
}

func (c *Client) buildHeader(request *fasthttp.Request) {

	c.header.Range(func(key, value any) bool {
		values := value.([]string)
		for _, v := range values {
			request.Header.Add(key.(string), v)
		}
		return true
	})

	if _, exist := c.header.Load("User-Agent"); !exist {
		request.Header.Add("User-Agent", util.GetRandomUA())
	}

}
