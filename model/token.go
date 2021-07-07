// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package model

import (
	"encoding/json"

	"github.com/hako/branca"
	"github.com/spf13/viper"
)

type UserClaims struct {
	UserName string `json:"user_name"`
	Email    string `json:"email"`
}

func init() {
	viper.SetDefault("setup_max_age", 86400)
	viper.SetDefault("reset_max_age", 3600)

	if !viper.IsSet("token_secret") {
		secret, err := GenerateSecret(16)
		if err != nil {
			panic(err)
		}
		viper.SetDefault("token_secret", secret)
	}
}

func NewToken(uid, email string, ttl uint32) (string, error) {
	claims := &UserClaims{
		UserName: uid,
		Email:    email,
	}

	jsonBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	b := branca.NewBranca(viper.GetString("token_secret"))
	b.SetTTL(ttl)

	token, err := b.EncodeToString(string(jsonBytes))
	if err != nil {
		return "", err
	}

	return token, nil
}

func ParseToken(token string, ttl uint32) (*UserClaims, error) {
	b := branca.NewBranca(viper.GetString("token_secret"))
	b.SetTTL(ttl)

	message, err := b.DecodeToString(token)
	if err != nil {
		return nil, err
	}

	var claims UserClaims
	err = json.Unmarshal([]byte(message), &claims)
	if err != nil {
		return nil, err
	}

	return &claims, nil
}
