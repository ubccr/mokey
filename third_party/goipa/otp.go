// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"errors"
	"time"

	"github.com/tidwall/gjson"
)

// OTP Token hash Algorithms supported by FreeIPA
const (
	AlgorithmSHA1   string = "sha1"
	AlgorithmSHA256        = "sha256"
	AlgorithmSHA384        = "sha384"
	AlgorithmSHA512        = "sha512"
)

// OTP Token types supported by FreeIPA
const (
	TokenTypeTOTP = "totp"
	TokenTypeHOTP = "hotp"
)

// OTPToken encapsulates FreeIPA otptokens
type OTPToken struct {
	DN          string    `json:"dn"`
	UUID        string    `json:"ipatokenuniqueid"`
	Algorithm   string    `json:"ipatokenotpalgorithm"`
	Digits      int       `json:"ipatokenotpdigits"`
	Owner       string    `json:"ipatokenowner"`
	TimeStep    int       `json:"ipatokentotptimestep"`
	ClockOffest int       `json:"ipatokentotpclockoffset"`
	ManagedBy   string    `json:"managedby_user"`
	Enabled     bool      `json:"-"`
	Type        string    `json:"type"`
	URI         string    `json:"uri"`
	Description string    `json:"description"`
	Vendor      string    `json:"ipatokenvendor"`
	Model       string    `json:"ipatokenmodel"`
	Serial      string    `json:"ipatokenserial"`
	NotBefore   time.Time `json:"ipatokennotbefore"`
	NotAfter    time.Time `json:"ipatokennotafter"`
}

var DefaultTOTPToken *OTPToken = &OTPToken{
	Type:      TokenTypeTOTP,
	Algorithm: AlgorithmSHA1,
	Digits:    6,
	TimeStep:  30,
}

func (t *OTPToken) DisplayName() string {
	if len(t.UUID) == 36 {
		return t.Owner + "-" + t.UUID[len(t.UUID)-6:]
	}
	return t.UUID
}

func (t *OTPToken) fromJSON(raw []byte) error {
	if !gjson.ValidBytes(raw) {
		return errors.New("invalid otp token record json")
	}

	res := gjson.ParseBytes(raw)

	t.DN = res.Get("dn").String()
	t.UUID = res.Get("ipatokenuniqueid.0").String()
	t.Algorithm = res.Get("ipatokenotpalgorithm.0").String()
	t.Digits = int(res.Get("ipatokenotpdigits.0").Int())
	t.Owner = res.Get("ipatokenowner.0").String()
	t.TimeStep = int(res.Get("ipatokentotptimestep.0").Int())
	t.ClockOffest = int(res.Get("ipatokentotpclockoffset.0").Int())
	t.ManagedBy = res.Get("managedby_user.0").String()
	t.Enabled = !res.Get("ipatokendisabled.0").Bool()
	t.Type = res.Get("type").String()
	t.URI = res.Get("uri").String()
	t.Description = res.Get("description.0").String()
	t.Vendor = res.Get("ipatokenvendor.0").String()
	t.Model = res.Get("ipatokenmodel.0").String()
	t.Serial = res.Get("ipatokenserial.0").String()
	t.NotBefore = ParseDateTime(res.Get("ipatokennotbefore.0.__datetime__").String())
	t.NotAfter = ParseDateTime(res.Get("ipatokennotafter.0.__datetime__").String())

	return nil
}

// Remove OTP token
func (c *Client) RemoveOTPToken(tokenUUID string) error {
	_, err := c.rpc("otptoken_del", []string{tokenUUID}, nil)

	if err != nil {
		return err
	}

	return nil
}

// Fetch OTP tokens by owner.
func (c *Client) FetchOTPTokens(owner string) ([]*OTPToken, error) {
	options := Options{
		"ipatokenowner": owner,
		"all":           true,
	}

	res, err := c.rpc("otptoken_find", []string{}, options)

	if err != nil {
		return nil, err
	}

	tokens := make([]*OTPToken, 0)

	data := gjson.ParseBytes(res.Result.Data)
	for _, t := range data.Array() {
		tok := new(OTPToken)
		err := tok.fromJSON([]byte(t.Raw))
		if err != nil {
			return nil, err
		}

		tokens = append(tokens, tok)
	}

	return tokens, nil
}

// Add OTP token. Returns new OTPToken
func (c *Client) AddOTPToken(token *OTPToken) (*OTPToken, error) {
	if token == nil {
		token = DefaultTOTPToken
	}
	if token.Type == "" {
		token.Type = DefaultTOTPToken.Type
	}
	if token.Algorithm == "" {
		token.Algorithm = DefaultTOTPToken.Algorithm
	}
	if token.Digits == 0 {
		token.Digits = DefaultTOTPToken.Digits
	}
	if token.TimeStep == 0 {
		token.TimeStep = DefaultTOTPToken.TimeStep
	}

	options := Options{
		"type":                 token.Type,
		"ipatokenotpalgorithm": token.Algorithm,
		"ipatokenotpdigits":    token.Digits,
		"ipatokentotptimestep": token.TimeStep,
		"no_qrcode":            true,
		"qrcode":               false,
		"no_members":           false,
		"all":                  true,
	}

	if token.Description != "" {
		options["description"] = token.Description
	}
	if token.Vendor != "" {
		options["ipatokenvendor"] = token.Vendor
	}
	if token.Model != "" {
		options["ipatokenmodel"] = token.Model
	}
	if token.Serial != "" {
		options["ipatokenserial"] = token.Serial
	}
	if !token.NotBefore.IsZero() {
		options["ipatokennotbefore"] = map[string]interface{}{
			"__datetime__": token.NotBefore.Format(IpaDatetimeFormat),
		}
	}
	if !token.NotAfter.IsZero() {
		options["ipatokennotafter"] = map[string]interface{}{
			"__datetime__": token.NotAfter.Format(IpaDatetimeFormat),
		}
	}

	res, err := c.rpc("otptoken_add", []string{}, options)

	if err != nil {
		return nil, err
	}

	tokenRec := new(OTPToken)
	err = tokenRec.fromJSON(res.Result.Data)
	if err != nil {
		return nil, err
	}

	return tokenRec, nil
}

// Enable OTP token.
func (c *Client) EnableOTPToken(tokenUUID string) error {
	options := Options{
		"ipatokendisabled": false,
		"all":              false,
	}

	_, err := c.rpc("otptoken_mod", []string{tokenUUID}, options)

	return err
}

// Disable OTP token.
func (c *Client) DisableOTPToken(tokenUUID string) error {
	options := Options{
		"ipatokendisabled": true,
		"all":              false,
	}

	_, err := c.rpc("otptoken_mod", []string{tokenUUID}, options)

	return err
}
