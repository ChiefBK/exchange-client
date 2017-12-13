package tracr_client

import (
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
	"fmt"
	"encoding/hex"
	"crypto/sha256"
	"encoding/base64"
)

const (
	DEFAULT_HTTPCLIENT_TIMEOUT = 30
)

func NewClient(apiKey, apiSecret, exchange, postBaseUrl, getBaseUrl string, throttle time.Duration) *Client {
	return &Client{apiKey, apiSecret, exchange, postBaseUrl, getBaseUrl, &http.Client{}, time.Tick(throttle)}
}

type Client struct {
	apiKey      string
	apiSecret   string
	exchange    string
	postBaseUrl string
	getBaseUrl  string
	httpClient  *http.Client
	throttle    <-chan time.Time
}

func (self *Client) doTimeoutRequest(req *http.Request) (*http.Response, error) {
	timeout := time.NewTimer(DEFAULT_HTTPCLIENT_TIMEOUT * time.Second)

	// Do the request in the background so we can check the timeout
	type result struct {
		resp *http.Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := self.httpClient.Do(req)
		done <- result{resp, err}
	}()
	// Wait for the read or the timeout
	select {
	case r := <-done:
		return r.resp, r.err
	case <-timeout.C:
		return nil, errors.New("timeout on reading data from Poloniex API")
	}
}

func (self *Client) makeRequest(method, requestUrlPath string, urlQueryArgs, bodyArgs, headerArgs map[string]string, respCh chan<- []byte, errCh chan<- error) {
	var req *http.Request
	body := []byte{}

	// create url args
	urlData := url.Values{}
	if urlQueryArgs != nil {
		for k, v := range urlQueryArgs {
			urlData.Add(k, v)
		}
	}

	var reqUrl string

	// create request url
	if method == "GET" {
		reqUrl = self.getBaseUrl
	} else if method == "POST" {
		reqUrl = self.postBaseUrl
	} else {
		respCh <- body
		errCh <- errors.New("must use GET or POST as method")
		return
	}
	reqUrl += requestUrlPath

	// add url params to url if they exist
	if len(urlData) > 0 {
		reqUrl += "?"
		reqUrl += urlData.Encode() // create string of url key-value data and append url args to request url
	}

	// create body data args
	bodyData := url.Values{}
	if bodyArgs != nil {
		for k, v := range bodyArgs {
			bodyData.Add(k, v)
		}
	}

	nonce := fmt.Sprintf("%d", time.Now().UnixNano()) // nonce equal to current unix timestamp
	bodyData.Add("nonce", nonce)                      // add to body
	requestBody := bodyData.Encode()                  // create string of body key-value data

	var secret []byte

	// create secret byte array based on exchange
	switch self.exchange {
	case "kraken":
		secret, _ = base64.StdEncoding.DecodeString(self.apiSecret)
	case "poloniex":
		secret = []byte(self.apiSecret)
	}

	mac := hmac.New(sha512.New, secret) // create hmac signed by secret

	var apiKeyKey string
	var apiSignKey string
	var sign string

	switch self.exchange {
	case "poloniex":
		apiKeyKey = "Key"
		apiSignKey = "Sign"
		mac.Write([]byte(requestBody))
		sign = hex.EncodeToString(mac.Sum(nil))
	case "kraken":
		apiKeyKey = "API-Key"
		apiSignKey = "API-Sign"
		h := sha256.New()
		h.Write([]byte(nonce + requestBody))
		mac.Write(append([]byte(requestUrlPath), h.Sum(nil)...))
		sign = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	}

	req, _ = http.NewRequest(method, reqUrl, strings.NewReader(requestBody))

	req.Header.Add(apiKeyKey, self.apiKey)
	req.Header.Add(apiSignKey, sign)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if headerArgs != nil {
		for k, v := range headerArgs {
			req.Header.Add(k, v)
		}
	}

	resp, err := self.doTimeoutRequest(req)
	if err != nil {
		respCh <- body
		errCh <- err
		return
	}

	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		respCh <- body
		errCh <- err
		return
	}
	if resp.StatusCode != 200 {
		respCh <- body
		errCh <- errors.New(resp.Status)
		return
	}

	respCh <- body
	errCh <- nil
	close(respCh)
	close(errCh)
}

// do prepare and process HTTP request to Poloniex API
func (self *Client) Do(method, requestUrlPath string, urlArgs, bodyArgs, headerArgs map[string]string) (response []byte, err error) {
	respCh := make(chan []byte)
	errCh := make(chan error)
	<-self.throttle
	go self.makeRequest(method, requestUrlPath, urlArgs, bodyArgs, headerArgs, respCh, errCh)
	response = <-respCh
	err = <-errCh
	return
}
