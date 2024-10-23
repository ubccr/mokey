// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"testing"
	"time"

	"github.com/gofiber/storage/memory/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestToken(t *testing.T) {
	secret, _ := GenerateSecret(32)
	viper.Set("email.token_secret", secret)
	viper.Set("email.token_max_age", uint32(3))

	assert := assert.New(t)

	email := "user@example.com"
	uid := "user"

	storage := memory.New()

	token, err := NewToken(uid, email, TokenPasswordReset, storage)
	if assert.NoError(err) {
		assert.Greater(len(token), 0)
	}

	claims, err := ParseToken(token, TokenPasswordReset, storage)
	if assert.NoError(err) {
		assert.Equal(claims.Username, uid)
		assert.Equal(claims.Email, email)
	}

	// Should error token already issued
	_, err = NewToken(uid, email, TokenPasswordReset, storage)
	assert.Error(err)

	time.Sleep(time.Second * 4)

	viper.Set("email.token_max_age", uint32(1))

	expToken, err := NewToken(uid, email, TokenPasswordReset, storage)
	if assert.NoError(err) {
		assert.Greater(len(token), 0)
	}

	time.Sleep(time.Second * 3)

	_, err = ParseToken(expToken, TokenPasswordReset, storage)
	assert.Error(err)
}
