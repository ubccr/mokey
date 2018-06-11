// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package model

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Token struct {
	UserName  string     `db:"user_name"`
	Email     string     `db:"email"`
	Token     string     `db:"token"`
	Attempts  int        `db:"attempts"`
	CreatedAt *time.Time `db:"created_at"`
}

func (db *DB) RandToken() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", nil
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (db *DB) computeMAC(salt, message, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	h.Write(salt)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func (db *DB) checkMAC(salt, message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	mac.Write(salt)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

func (db *DB) SignToken(salt, token string) string {
	mac := db.computeMAC([]byte(salt), []byte(token), []byte(viper.GetString("auth_key")))
	return fmt.Sprintf("%s.%s", token, mac)
}

func (db *DB) VerifyToken(salt, signedToken string) (string, bool) {
	parts := strings.SplitN(signedToken, ".", 2)
	if len(parts) != 2 {
		return "", false
	}

	token, b64mac := parts[0], parts[1]

	if len(token) != 22 || len(b64mac) == 0 {
		return "", false
	}

	mac, err := base64.RawURLEncoding.DecodeString(b64mac)
	if err != nil {
		return "", false
	}

	if db.checkMAC([]byte(salt), []byte(token), mac, []byte(viper.GetString("auth_key"))) {
		return token, true
	}

	return "", false
}

func (db *DB) FetchTokenByUser(uid string, maxAge int) (*Token, error) {
	t := Token{}
	err := db.Get(&t, "select user_name,token,attempts,email,created_at from token where user_name = ? and timestampdiff(SECOND, created_at, now()) <= ?", uid, maxAge)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}

	return &t, nil
}

func (db *DB) FetchToken(token string, maxAge int) (*Token, error) {
	t := Token{}
	err := db.Get(&t, "select user_name,token,attempts,email from token where token = ? and timestampdiff(SECOND, created_at, now()) <= ?", token, maxAge)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}

	return &t, nil
}

func (db *DB) CreateToken(uid, email string) (*Token, error) {
	tok, err := db.RandToken()
	if err != nil {
		return nil, err
	}

	t := Token{UserName: uid, Email: email, Token: tok}
	_, err = db.NamedExec("replace into token (user_name,email,token,attempts,created_at) values (:user_name, :email, :token, 0, now())", t)
	if err != nil {
		return nil, err
	}

	return &t, nil
}

func (db *DB) IncrementToken(token string) error {
	_, err := db.Exec("update token set attempts = attempts + 1 where token = ?", token)
	if err == sql.ErrNoRows {
		return ErrNotFound
	} else if err != nil {
		return err
	}

	return nil
}

func (db *DB) DestroyToken(token string) error {
	_, err := db.Exec("delete from token where token = ?", token)
	if err == sql.ErrNoRows {
		return ErrNotFound
	} else if err != nil {
		return err
	}

	return nil
}

func (db *DB) DestroyTokenByUser(uid string) error {
	_, err := db.Exec("delete from token where user_name = ?", uid)
	if err == sql.ErrNoRows {
		return ErrNotFound
	} else if err != nil {
		return err
	}

	return nil
}
