package wxpay

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"
)

const bodyType = "application/xml; charset=utf-8"

type Client struct {
	seclient *http.Client

	AppId  string
	MchId  string
	ApiKey string
}

func NewClient(appId, mchId, apiKey string) *Client {
	return &Client{
		AppId:  appId,
		MchId:  mchId,
		ApiKey: apiKey,
	}
}

func (c *Client) WithCert(certFile, keyFile, rootcaFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	data, err := ioutil.ReadFile(rootcaFile)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM(data)
	if !ok {
		return errors.New("failed to parse root certificate")
	}
	c.seclient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      pool,
			},
		},
	}
	return nil
}

func (c *Client) Post(url string, params Params, tls bool) (Params, error) {
	var hc *http.Client
	if tls {
		hc = c.seclient
	} else {
		hc = http.DefaultClient
	}
	resp, err := hc.Post(url, bodyType, c.Encode(params))
	if err != nil {
		return nil, err
	}
	return c.Decode(resp.Body), nil
}

func (c *Client) Decode(r io.Reader) Params {
	var (
		d      *xml.Decoder
		start  *xml.StartElement
		params Params
	)
	d = xml.NewDecoder(r)
	params = make(Params)
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			start = &t
		case xml.CharData:
			if t = bytes.TrimSpace(t); len(t) > 0 {
				params.SetString(start.Name.Local, string(t))
			}
		}
	}
	return params
}

func (c *Client) Encode(params Params) io.Reader {
	var buf bytes.Buffer
	buf.WriteString(`<xml>`)
	for k, v := range params {
		buf.WriteString(`<`)
		buf.WriteString(k)
		buf.WriteString(`><![CDATA[`)
		buf.WriteString(v)
		buf.WriteString(`]]></`)
		buf.WriteString(k)
		buf.WriteString(`>`)
	}
	buf.WriteString(`</xml>`)
	return &buf
}

func (c *Client) CheckSign(params Params) bool {
	return params.GetString("sign") == c.Sign(params)
}

func (c *Client) Sign(params Params) string {
	var keys = make([]string, 0, len(params))
	for k, _ := range params {
		if k != "sign" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	for _, k := range keys {
		if len(params.GetString(k)) > 0 {
			buf.WriteString(k)
			buf.WriteString(`=`)
			buf.WriteString(params.GetString(k))
			buf.WriteString(`&`)
		}
	}
	buf.WriteString(`key=`)
	buf.WriteString(c.ApiKey)

	res := fmt.Sprintf("%x", md5.Sum(buf.Bytes()))
	return strings.ToUpper(res)
}
