# 微信支付商户平台SDK for Go

[![GoDoc](https://godoc.org/github.com/go-with/wxpay?status.svg)](https://godoc.org/github.com/go-with/wxpay)
[![Build Status](https://travis-ci.org/go-with/wxpay.svg?branch=master)](https://travis-ci.org/go-with/wxpay)

这是一个使用Go语言编写的微信支付商户平台SDK

## 举个栗子

以查询企业付款API为栗

```Go
package main

import (
	"log"

	"gopkg.in/go-with/wxpay.v1"
)

const (
	appId  = "" // 微信公众平台应用ID
	mchId  = "" // 微信支付商户平台商户号
	apiKey = "" // 微信支付商户平台API密钥

	// 微信支付商户平台证书路径
	certFile   = "cert/apiclient_cert.pem"
	keyFile    = "cert/apiclient_key.pem"
	rootcaFile = "cert/rootca.pem"
)

func main() {
	c := wxpay.NewClient(appId, mchId, apiKey)

	// 附着商户证书
	err := c.WithCert(certFile, keyFile, rootcaFile)
	if err != nil {
		log.Fatal(err)
	}

	params := make(wxpay.Params)
	// 查询企业付款接口请求参数
	params.SetString("appid", c.AppId)
	params.SetString("mch_id", c.MchId)
	params.SetString("nonce_str", "5K8264ILTKCH16CQ2502SI8ZNMTM67VS")  // 随机字符串
	params.SetString("partner_trade_no", "10000098201411111234567890") // 商户订单号
	params.SetString("sign", c.Sign(params))                           // 签名

	// 查询企业付款接口请求URL
	url := "https://api.mch.weixin.qq.com/mmpaymkttransfers/gettransferinfo"

	// 发送查询企业付款请求
	ret, err := c.Post(url, params, true)
	if err != nil {
		log.Fatal(err)
	}

	log.Print(ret)
}

```

## 相关链接

[微信支付商户平台](https://pay.weixin.qq.com/)

[微信支付商户平台开发者文档](https://pay.weixin.qq.com/wiki/doc/api/index.html)

## 许可协议

[The MIT License (MIT)](LICENSE)
