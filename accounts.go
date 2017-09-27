// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package main

import (
	"database/sql"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"
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

	db, err := model.NewDB(viper.GetString("driver"), viper.GetString("dsn"))
	if err != nil {
		return nil, err
	}

	token, err := model.CreateToken(db, uid, string(userRec.Email))
	if err != nil {
		return nil, err
	}

	return token, nil
}

func NewAccountEmail(uid string) {
	ctx, err := app.NewAppContext()
	if err != nil {
		log.Fatal(err.Error())
	}

	token, err := createToken(uid)
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

	err = model.RemoveAnswer(ctx.DB, uid)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":   uid,
			"error": err,
		}).Error("failed to remove security answer")
	}

	err = handlers.RemoveAllOTPTokens(uid, "")
	if err != nil {
		log.WithFields(log.Fields{
			"uid":   uid,
			"error": err,
		}).Error("failed to remove all OTP tokens")
	}
}

func ResetPasswordEmail(uid string) {
	db, err := model.NewDB(viper.GetString("driver"), viper.GetString("dsn"))
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

func Status(uid string) {
	db, err := model.NewDB(viper.GetString("driver"), viper.GetString("dsn"))
	if err != nil {
		log.Fatal(err.Error())
	}

	token, err := model.FetchTokenByUser(db, uid, viper.GetInt("setup_max_age"))
	if err != nil && err != sql.ErrNoRows {
		log.WithFields(log.Fields{
			"uid":   uid,
			"error": err,
		}).Error("Failed to fetch token")
		return
	}

	answer, err := model.FetchAnswer(db, uid)
	if err != nil && err != sql.ErrNoRows {
		log.WithFields(log.Fields{
			"uid":   uid,
			"error": err,
		}).Error("Failed to fetch security answer")
		return
	}

	fmt.Printf("Status for user: %s\n", uid)
	fmt.Printf("-----------------------------------\n")
	if answer != nil {
		fmt.Printf("Security question set on %s\n", answer.CreatedAt.Format("Jan 02, 2006 15:04:05"))
	} else {
		fmt.Printf("No security question set\n")
	}
	if token != nil {
		fmt.Printf("Active token created at: %s\n", token.CreatedAt.Format("Jan 02, 2006 15:04:05"))
	} else {
		fmt.Printf("No token found\n")
	}
}
