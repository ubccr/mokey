// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package model

import (
	log "github.com/Sirupsen/logrus"
	"github.com/jmoiron/sqlx"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type OTPToken struct {
	UserName  string `db:"user_name"`
	URI       string `db:"uri"`
	Confirmed bool   `db:"confirmed"`
}

func (t *OTPToken) Validate(code string) bool {
	key, err := otp.NewKeyFromURL(t.URI)
	if err != nil {
		log.Error("Failed to parse TOTP URI")
		return false
	}
	return totp.Validate(code, key.Secret())
}

func FetchConfirmedOTPToken(db *sqlx.DB, uid string) (*OTPToken, error) {
	token := OTPToken{}
	err := db.Get(&token, "select user_name,uri from otp_token where user_name = ? and confirmed = 1", uid)
	if err != nil {
		return nil, err
	}

	return &token, nil
}

func FetchUnconfirmedOTPToken(db *sqlx.DB, uid string) (*OTPToken, error) {
	token := OTPToken{}
	err := db.Get(&token, "select user_name,uri from otp_token where user_name = ? and confirmed = 0", uid)
	if err != nil {
		return nil, err
	}

	return &token, nil
}

func StoreOTPToken(db *sqlx.DB, uid, uri string) error {
	_, err := db.Exec("replace into otp_token (user_name,uri,created_at, confirmed) values (?, ?, now(), 0)", uid, uri)
	if err != nil {
		return err
	}

	return nil
}

func ConfirmOTPToken(db *sqlx.DB, uid string) error {
	_, err := db.Exec("update otp_token set confirmed = 1 where user_name = ?", uid)
	if err != nil {
		return err
	}

	return nil
}

func RemoveOTPToken(db *sqlx.DB, uid string) error {
	_, err := db.Exec("delete from otp_token where user_name = ?", uid)
	if err != nil {
		return err
	}

	return nil
}
