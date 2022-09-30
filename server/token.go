// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/essentialkaos/branca"
	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
)

type Token struct {
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Timestamp time.Time `json:"-"`
}

func GenerateSecret(n int) (string, error) {
	secret := make([]byte, n)
	_, err := rand.Read(secret)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(secret), nil
}

func NewToken(username, email, prefix string, storage fiber.Storage) (string, error) {
	tokenIssued, err := storage.Get(prefix + TokenIssuedPrefix + username)
	if tokenIssued != nil {
		return "", errors.New("token already issued")
	}

	claims := &Token{
		Username: username,
		Email:    email,
	}

	jsonBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	key, err := hex.DecodeString(viper.GetString("token_secret"))
	if err != nil {
		return "", err
	}

	b, err := branca.NewBranca(key)
	if err != nil {
		return "", err
	}

	b.SetTTL(viper.GetUint32("token_max_age"))

	token, err := b.EncodeToString(jsonBytes)
	if err != nil {
		return "", err
	}

	storage.Set(prefix+TokenIssuedPrefix+username, []byte("true"), time.Until(time.Now().Add(time.Duration(viper.GetInt("token_max_age"))*time.Second)))

	return token, nil
}

func ParseToken(token, prefix string, storage fiber.Storage) (*Token, error) {
	tokenUsed, err := storage.Get(prefix + TokenUsedPrefix + token)
	if tokenUsed != nil {
		return nil, errors.New("token already used")
	}

	key, err := hex.DecodeString(viper.GetString("token_secret"))
	if err != nil {
		return nil, err
	}

	b, err := branca.NewBranca(key)
	if err != nil {
		return nil, err
	}

	b.SetTTL(viper.GetUint32("token_max_age"))

	brancaToken, err := b.DecodeString(token)
	if err != nil {
		return nil, err
	}

	if b.IsExpired(brancaToken) {
		return nil, errors.New("Token expired")
	}

	var tk Token
	err = json.Unmarshal([]byte(brancaToken.Payload()), &tk)
	if err != nil {
		return nil, err
	}

	tk.Timestamp = brancaToken.Timestamp()

	return &tk, nil
}
