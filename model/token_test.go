// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestToken(t *testing.T) {
	assert := assert.New(t)

	email := "user@example.com"
	uid := "user"
	ttl := uint32(3600)

	token, err := NewToken(uid, email, ttl)
	if assert.NoError(err) {
		assert.Greater(len(token), 0)
	}

	claims, err := ParseToken(token, ttl)
	if assert.NoError(err) {
		assert.Equal(claims.UserName, uid)
		assert.Equal(claims.Email, email)
	}

	expToken, err := NewToken(uid, email, 1)
	if assert.NoError(err) {
		assert.Greater(len(token), 0)
	}

	time.Sleep(time.Second * 2)

	_, err = ParseToken(expToken, 1)
	assert.Error(err)
}
