// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"testing"
	"time"

	"github.com/gofiber/storage/memory"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestToken(t *testing.T) {
	secret, _ := GenerateSecret(32)
	viper.Set("token_secret", secret)
	viper.Set("token_max_age", uint32(3))

	assert := assert.New(t)

	email := "user@example.com"
	uid := "user"

	storage := memory.New()

	token, err := NewToken(uid, email, storage)
	if assert.NoError(err) {
		assert.Greater(len(token), 0)
	}

	claims, err := ParseToken(token, storage)
	if assert.NoError(err) {
		assert.Equal(claims.Username, uid)
		assert.Equal(claims.Email, email)
	}

	// Should error token already issued
	_, err = NewToken(uid, email, storage)
	assert.Error(err)

	time.Sleep(time.Second * 4)

	viper.Set("token_max_age", uint32(1))

	expToken, err := NewToken(uid, email, storage)
	if assert.NoError(err) {
		assert.Greater(len(token), 0)
	}

	time.Sleep(time.Second * 3)

	_, err = ParseToken(expToken, storage)
	assert.Error(err)
}
