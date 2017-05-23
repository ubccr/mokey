// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package model

import (
	"database/sql"
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

	_, err = FetchTokenByUser(db, "usernotexist", 1800)
	if err != sql.ErrNoRows {
		t.Error(err)
	}

	_, err = FetchToken(db, "notoken", 1800)
	if err != sql.ErrNoRows {
		t.Error(err)
	}

	uid := "mokeytestuser"
	email := "mokeytestuser@localhost"

	viper.Set("secret_key", goodSecret)
	token, err := CreateToken(db, uid, email)
	if err != nil {
		t.Error(err)
	}

	tok, err := FetchTokenByUser(db, uid, 1800)
	if err != nil {
		t.Error(err)
	}

	if tok.Token != token.Token {
		t.Errorf("Incorrect token: got %d should be %d", tok.Token, token.Token)
	}

	st := SignToken(goodSalt, tok.Token)

	_, check := VerifyToken(badSalt, st)
	if check {
		t.Errorf("Validated token with bad salt")
	}

	viper.Set("secret_key", badSecret)
	_, check = VerifyToken(goodSalt, st)
	if check {
		t.Errorf("Validated token with bad secret")
	}

	viper.Set("secret_key", goodSecret)
	vt, check := VerifyToken(goodSalt, st)
	if !check {
		t.Errorf("Failed to validate good signed token")
	}

	if vt != tok.Token {
		t.Errorf("Incorrect validated token: got %d should be %d", vt, tok.Token)
	}

	err = DestroyToken(db, tok.Token)
	if err != nil {
		t.Error(err)
	}

	_, err = FetchTokenByUser(db, uid, 1800)
	if err != sql.ErrNoRows {
		t.Error(err)
	}
}
