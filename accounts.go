package main

import (
    "fmt"
    "errors"
    "github.com/spf13/viper"
    "github.com/ubccr/mokey/model"
    "github.com/Sirupsen/logrus"
)

func createToken(uid string) (*model.Token, error) {
    client := NewIpaClient(true)
    userRec, err := client.UserShow(uid)
    if err != nil {
        return nil, err
    }

    if len(userRec.Email) == 0 {
        return nil, errors.New("User missing email address")
    }

    db, err := NewDb()
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
        logrus.Fatal(err.Error())
    }

    app, err := NewApplication()
    if err != nil {
        logrus.Fatal(err.Error())
    }

    vars := map[string]interface{}{
            "link": fmt.Sprintf("%s/auth/setup/%s", viper.GetString("email_link_base"), token.Token)}

    err = app.SendEmail(token.Email, fmt.Sprintf("[%s] New Account Setup", viper.GetString("email_prefix")), "setup-account.txt", vars)
    if err != nil {
        logrus.WithFields(logrus.Fields{
            "uid": uid,
            "error": err,
        }).Error("failed send email to user")
    }
}

func ResetPasswordEmail(uid string) {
    db, err := NewDb()
    if err != nil {
        logrus.Fatal(err.Error())
    }

    _, err = model.FetchAnswer(db, uid)
    if err != nil {
        logrus.WithFields(logrus.Fields{
            "uid": uid,
            "error": err,
        }).Error("Failed to fetch security answer. Please run newacct to setup user account.")
        return
    }

    token, err := createToken(uid)
    if err != nil {
        logrus.Fatal(err.Error())
    }

    app, err := NewApplication()
    if err != nil {
        logrus.Fatal(err.Error())
    }

    vars := map[string]interface{}{
            "link": fmt.Sprintf("%s/auth/resetpw/%s", viper.GetString("email_link_base"), token.Token)}

    err = app.SendEmail(token.Email, fmt.Sprintf("[%s] Please reset your password", viper.GetString("email_prefix")), "reset-password.txt", vars)
    if err != nil {
        logrus.WithFields(logrus.Fields{
            "uid": uid,
            "error": err,
        }).Error("failed send email to user")
    }
}
