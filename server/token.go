// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
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

func GenerateSecretString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-!@#$%^&*(){}[]"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
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

	key, err := hex.DecodeString(viper.GetString("email.token_secret"))
	if err != nil {
		return "", err
	}

	b, err := branca.NewBranca(key)
	if err != nil {
		return "", err
	}

	b.SetTTL(viper.GetUint32("email.token_max_age"))

	token, err := b.EncodeToString(jsonBytes)
	if err != nil {
		return "", err
	}

	storage.Set(prefix+TokenIssuedPrefix+username, []byte("true"), time.Until(time.Now().Add(time.Duration(viper.GetInt("email.token_max_age"))*time.Second)))

	return token, nil
}

func ParseToken(token, prefix string, storage fiber.Storage) (*Token, error) {
	tokenUsed, err := storage.Get(prefix + TokenUsedPrefix + token)
	if tokenUsed != nil {
		return nil, errors.New("token already used")
	}

	key, err := hex.DecodeString(viper.GetString("email.token_secret"))
	if err != nil {
		return nil, err
	}

	b, err := branca.NewBranca(key)
	if err != nil {
		return nil, err
	}

	b.SetTTL(viper.GetUint32("email.token_max_age"))

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
