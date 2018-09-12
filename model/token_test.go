// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package model

import (
	"testing"

	"github.com/spf13/viper"
)

func TestToken(t *testing.T) {
	goodSecret := "mysecretkey"
	badSecret := "badsecretkey"
	goodSalt := "goodsalt"
	badSalt := "badsalt"

	db, err := newTestDB()
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.FetchTokenByUser("usernotexist", 1800)
	if err != ErrNotFound {
		t.Error(err)
	}

	_, err = db.FetchToken("notoken", 1800)
	if err != ErrNotFound {
		t.Error(err)
	}

	uid := "mokeytestuser"
	email := "mokeytestuser@localhost"

	viper.Set("auth_key", goodSecret)
	token, err := db.CreateToken(uid, email)
	if err != nil {
		t.Error(err)
	}

	tok, err := db.FetchTokenByUser(uid, 1800)
	if err != nil {
		t.Error(err)
	}

	if tok.Token != token.Token {
		t.Errorf("Incorrect token: got %s should be %s", tok.Token, token.Token)
	}

	st := db.SignToken(goodSalt, tok.Token)

	_, check := db.VerifyToken(badSalt, st)
	if check {
		t.Errorf("Validated token with bad salt")
	}

	viper.Set("auth_key", badSecret)
	_, check = db.VerifyToken(goodSalt, st)
	if check {
		t.Errorf("Validated token with bad secret")
	}

	viper.Set("auth_key", goodSecret)
	vt, check := db.VerifyToken(goodSalt, st)
	if !check {
		t.Errorf("Failed to validate good signed token")
	}

	if vt != tok.Token {
		t.Errorf("Incorrect validated token: got %s should be %s", vt, tok.Token)
	}

	err = db.DestroyToken(tok.Token)
	if err != nil {
		t.Error(err)
	}

	_, err = db.FetchTokenByUser(uid, 1800)
	if err != ErrNotFound {
		t.Error(err)
	}
}
