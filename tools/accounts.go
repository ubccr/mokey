// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package tools

import (
	"errors"
	"fmt"

	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/model"
	"github.com/ubccr/mokey/util"
)

func ResetPasswordEmail(uid string) error {
	db, err := model.NewDB(viper.GetString("driver"), viper.GetString("dsn"))
	if err != nil {
		return err
	}

	client := ipa.NewDefaultClient()
	err = client.LoginWithKeytab(viper.GetString("keytab"), viper.GetString("ktuser"))
	if err != nil {
		return err
	}

	userRec, err := client.UserShow(uid)
	if err != nil {
		return err
	}

	if len(userRec.Email) == 0 {
		return errors.New("No email address provided for that username")
	}

	emailer, err := util.NewEmailer(db)
	if err != nil {
		return err
	}

	err = emailer.SendResetPasswordEmail(uid, string(userRec.Email))
	if err != nil {
		return err
	}

	return nil
}

func Status(uid string) error {
	db, err := model.NewDB(viper.GetString("driver"), viper.GetString("dsn"))
	if err != nil {
		return err
	}

	token, err := db.FetchTokenByUser(uid, viper.GetInt("setup_max_age"))
	if err != nil && err != model.ErrNotFound {
		return err
	}

	fmt.Printf("Status for user: %s\n", uid)
	fmt.Printf("-----------------------------------\n")
	if token != nil {
		fmt.Printf("Active token created at: %s\n", token.CreatedAt.Format("Jan 02, 2006 15:04:05"))
	} else {
		fmt.Printf("No token found\n")
	}

	return nil
}
