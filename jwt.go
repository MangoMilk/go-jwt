package Jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/MangoMilk/go-kit/encrypt"
	"reflect"
	"strings"
)

const (
	dot = "."

	HS256 = "HS256"
	HS1   = "HS1"

	defaultEncryptType = HS256

	errMsgPrefix            = "[Jwt Error] "
	errMsgNotSupportEncrypt = errMsgPrefix + "not support %v encrypt"
	errMsgSignError         = errMsgPrefix + "sign error"
	errMsgJwtIsEmpty        = errMsgPrefix + "jwt is empty"
	errMsgJwtFormatError    = errMsgPrefix + "jwt format error"
)

//	Payload
//
//
//
//
//
type StandardPayload struct {
	Iss string `json:"iss"` // 签发者
	Iat string `json:"iat"` // 签发时间
	Exp string `json:"exp"` // 过期时间
	Aud string `json:"aud"` // 接收jwt的一方
	Sub string `json:"sub"` // jwt面向的用户
	Nbf string `json:"nbf"` // 定义在什么时间之前，该jwt都是不可用的
	Jti string `json:"jti"` // jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击
}

type Payload struct {
	StandardPayload
	Addition map[string]interface{}
}

func (p *Payload) SetIss(iss string) {
	p.Iss = iss
}

func (p *Payload) SetIat(iat string) {
	p.Iat = iat
}

func (p *Payload) SetExp(exp string) {
	p.Exp = exp
}

func (p *Payload) SetAud(aud string) {
	p.Aud = aud
}

func (p *Payload) SetSub(sub string) {
	p.Sub = sub
}

func (p *Payload) SetNbf(nbf string) {
	p.Nbf = nbf
}

func (p *Payload) SetJti(jti string) {
	p.Jti = jti
}

func (p *Payload) ToString() string {
	p.Addition["iss"] = p.Iss
	p.Addition["iat"] = p.Iat
	p.Addition["exp"] = p.Exp
	p.Addition["aud"] = p.Aud
	p.Addition["sub"] = p.Sub
	p.Addition["nbf"] = p.Nbf
	p.Addition["jti"] = p.Jti

	jsonByte, _ := json.Marshal(p.Addition)

	return base64.StdEncoding.EncodeToString(jsonByte)
}

//	Header
//
//
//
//
//
type Header struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

func (h *Header) SetTyp(typ string) {
	h.Typ = typ
}

func (h *Header) SetAlg(alg string) error {

	if alg != HS256 && alg != HS1 {
		return errors.New(fmt.Sprintf(errMsgNotSupportEncrypt, alg))
	}

	h.Alg = alg

	return nil
}

func (h *Header) ToString() string {
	if h.Alg == "" {
		h.Alg = defaultEncryptType
	}

	jsonByte, _ := json.Marshal(h)

	return base64.StdEncoding.EncodeToString(jsonByte)
}

//	jwt
//
//
//
//
//
type jwt struct {
	Payload Payload
	Header  Header
	Sign    string
}

func NewJwt() *jwt {
	return &jwt{
		Payload: Payload{
			StandardPayload: StandardPayload{},
			Addition:        make(map[string]interface{}),
		},
		Header: Header{},
	}
}

// set standard payload
func (token *jwt) SetStandardPayload(payload StandardPayload) {
	token.Payload.StandardPayload = payload
}

// set addition payload
func (token *jwt) SetAdditionPayload(payload map[string]interface{}) {
	token.Payload.Addition = payload
}

// set header
func (token *jwt) SetHeader(header Header) error {
	if header.Alg == "" {
		header.Alg = HS256
	}
	//token.Header = header
	err := token.Header.SetAlg(header.Alg)
	if err != nil {
		return err
	}
	token.Header.SetTyp(header.Typ)

	return nil
}

// process jwt
func (token *jwt) generateSign(secret string) (sign string) {

	switch token.Header.Alg {
	case HS256:
		sign = encrypt.HmacSHA256(token.Header.ToString()+dot+token.Payload.ToString(), secret)
		break
	case HS1:
		sign = encrypt.HmacSHA1(token.Header.ToString()+dot+token.Payload.ToString(), secret)
		break
	default:
		sign = ""
	}
	return
}

func (token *jwt) Signature(secret string) error {
	token.Sign = token.generateSign(secret)
	if token.Sign == "" {
		return errors.New(errMsgSignError+", please set a encrypt alg first")
	}

	return nil
}

func (token *jwt) VerifySign(secret string) error {
	if token.Sign == "" || token.generateSign(secret) != token.Sign {
		return errors.New(errMsgSignError)
	}

	return nil
}

func (token *jwt) Generate() string {
	return token.Header.ToString() + dot + token.Payload.ToString() + dot + token.Sign
}

func (token *jwt) Resolve(jwtToken string) error {
	if jwtToken == "" {
		return errors.New(errMsgJwtIsEmpty)
	}

	var jwtArr []string = strings.Split(jwtToken, dot)

	if len(jwtArr) < 3 || jwtArr[0] == "" || jwtArr[1] == "" || jwtArr[2] == "" {
		return errors.New(errMsgJwtFormatError)
	}

	resolveHeaderErr := token.resolveHeader(jwtArr[0], &token.Header)
	if resolveHeaderErr != nil {
		return resolveHeaderErr
	}

	resolvePayloadErr := token.resolvePayload(jwtArr[1], &token.Payload)
	if resolvePayloadErr != nil {
		return resolvePayloadErr
	}

	token.Sign = jwtArr[2]

	return nil
}

func (token *jwt) resolvePayload(payloadStr string, payload *Payload) error {
	plainText, err := base64.StdEncoding.DecodeString(payloadStr)
	if err != nil {
		return err
	}
	var payloadMap = make(map[string]interface{})
	jsonUnmarshalErr := json.Unmarshal(plainText, &payloadMap)
	if jsonUnmarshalErr != nil {
		return jsonUnmarshalErr
	}

	payload.StandardPayload = StandardPayload{
		Iss: payloadMap["iss"].(string),
		Iat: payloadMap["iat"].(string),
		Exp: payloadMap["exp"].(string),
		Aud: payloadMap["aud"].(string),
		Sub: payloadMap["sub"].(string),
		Nbf: payloadMap["nbf"].(string),
		Jti: payloadMap["jti"].(string),
	}

	standardPayloadType := reflect.TypeOf(payload.StandardPayload)

	for i := 0; i < standardPayloadType.NumField(); i++ {
		delete(payloadMap, standardPayloadType.Field(i).Tag.Get("json"))
	}

	payload.Addition = payloadMap

	return nil
}

func (token *jwt) resolveHeader(headerStr string, header *Header) error {
	plainText, err := base64.StdEncoding.DecodeString(headerStr)
	if err != nil {
		return err
	}

	jsonUnmarshalErr := json.Unmarshal(plainText, header)
	if jsonUnmarshalErr != nil {
		return jsonUnmarshalErr
	}

	return nil
}

func (token *jwt) ToString() string {
	return token.Header.ToString() + dot + token.Payload.ToString() + dot + token.Sign
}
