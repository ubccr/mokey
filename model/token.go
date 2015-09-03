// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package model

import (
    "fmt"
    "strings"
    "crypto/rand"
    "crypto/sha256"
    "crypto/hmac"
    "encoding/base64"

    "github.com/jmoiron/sqlx"
    "github.com/spf13/viper"
)

type Token struct {
    UserName             string      `db:"user_name"`
    Email                string      `db:"email"`
    Token                string      `db:"token"`
    Attempts             int         `db:"attempts"`
}

func randToken() string {
    b := make([]byte, 32)
    rand.Read(b)
    return fmt.Sprintf("%x", b)
}

func computeMAC(salt, message, key []byte) string {
    h := hmac.New(sha256.New, key)
    h.Write(message)
    h.Write(salt)
    return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func checkMAC(salt, message, messageMAC, key []byte) bool {
    mac := hmac.New(sha256.New, key)
    mac.Write(message)
    mac.Write(salt)
    expectedMAC := mac.Sum(nil)
    return hmac.Equal(messageMAC, expectedMAC)
}

func SignToken(salt, token string) string {
    mac := computeMAC([]byte(salt), []byte(token), []byte(viper.GetString("secret_key")))
    return fmt.Sprintf("%s.%s", token, mac)
}

func VerifyToken(salt, signedToken string) (string, bool) {
    parts := strings.SplitN(signedToken, ".", 2)
    if len(parts) != 2 {
        return "", false
    }

    token, b64mac := parts[0], parts[1]

    if len(token) != 64 || len(b64mac) == 0 {
        return "", false
    }

    mac, err := base64.RawURLEncoding.DecodeString(b64mac)
    if err != nil {
        return "", false
    }

    if checkMAC([]byte(salt), []byte(token), mac, []byte(viper.GetString("secret_key"))) {
        return token, true
    }

    return "", false
}

func FetchTokenByUser(db *sqlx.DB, uid string, maxAge int) (*Token, error) {
    t := Token{}
    err := db.Get(&t, "select user_name,token,attempts,email from token where user_name = ? and timestampdiff(SECOND, created_at, now()) <= ?", uid, maxAge)
    if err != nil {
        return nil, err
    }

    return &t, nil
}

func FetchToken(db *sqlx.DB, token string, maxAge int) (*Token, error) {
    t := Token{}
    err := db.Get(&t, "select user_name,token,attempts,email from token where token = ? and timestampdiff(SECOND, created_at, now()) <= ?", token, maxAge)
    if err != nil {
        return nil, err
    }

    return &t, nil
}

func NewToken(db *sqlx.DB, uid, email string) (*Token, error) {
    t := Token{UserName: uid, Email: email, Token: randToken()}
    _, err := db.NamedExec("replace into token (user_name,email, token,attempts,created_at) values (:user_name, :email, :token, 0, now())", t)
    if err != nil {
        return nil, err
    }

    return &t, nil
}

func IncrementToken(db *sqlx.DB, token string) (error) {
    _, err := db.Exec("update token set attempts = attempts + 1 where token = ?", token)
    if err != nil {
        return err
    }

    return nil
}

func DestroyToken(db *sqlx.DB, token string) (error) {
    _, err := db.Exec("delete from token where token = ?", token)
    if err != nil {
        return err
    }

    return nil
}
