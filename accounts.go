// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"

	log "github.com/Sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/mokey/app"
	"github.com/ubccr/mokey/handlers"
	"github.com/ubccr/mokey/model"
)

func createToken(uid string) (*model.Token, error) {
	client := app.NewIpaClient(true)
	userRec, err := client.UserShow(uid)
	if err != nil {
		return nil, err
	}

	if len(userRec.Email) == 0 {
		return nil, errors.New("User missing email address")
	}

	db, err := app.NewDb()
	if err != nil {
		return nil, err
	}

	token, err := model.NewToken(db, uid, string(userRec.Email))
	if err != nil {
		return nil, err
	}

	return token, nil
}

func NewAccountEmail(uid string) {
	token, err := createToken(uid)
	if err != nil {
		log.Fatal(err.Error())
	}

	ctx, err := app.NewAppContext()
	if err != nil {
		log.Fatal(err.Error())
	}

	vars := map[string]interface{}{
		"uid":  uid,
		"link": fmt.Sprintf("%s/auth/setup/%s", viper.GetString("email_link_base"), model.SignToken(app.AccountSetupSalt, token.Token))}

	err = ctx.SendEmail(token.Email, fmt.Sprintf("[%s] New Account Setup", viper.GetString("email_prefix")), "setup-account.txt", vars)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":   uid,
			"error": err,
		}).Error("failed send email to user")
	}
}

func ResetPasswordEmail(uid string) {
	db, err := app.NewDb()
	if err != nil {
		log.Fatal(err.Error())
	}

	_, err = model.FetchAnswer(db, uid)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":   uid,
			"error": err,
		}).Error("Failed to fetch security answer. Please run newacct to setup user account.")
		return
	}

	token, err := createToken(uid)
	if err != nil {
		log.Fatal(err.Error())
	}

	ctx, err := app.NewAppContext()
	if err != nil {
		log.Fatal(err.Error())
	}

	vars := map[string]interface{}{
		"link": fmt.Sprintf("%s/auth/resetpw/%s", viper.GetString("email_link_base"), model.SignToken(app.ResetSalt, token.Token))}

	err = ctx.SendEmail(token.Email, fmt.Sprintf("[%s] Please reset your password", viper.GetString("email_prefix")), "reset-password.txt", vars)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":   uid,
			"error": err,
		}).Error("failed send email to user")
	}
}

func DisableTOTP(uid string) {
	ctx, err := app.NewAppContext()
	if err != nil {
		log.Fatal(err.Error())
	}

	err = handlers.DisableTOTP(ctx, uid, "")
	if err != nil {
		log.Fatal(err.Error())
	}

	log.Infof("TOTP disabled for user: %s", uid)
}
