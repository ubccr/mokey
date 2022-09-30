// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"net/textproto"
	"path/filepath"
	"text/template"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/mileusna/useragent"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
)

const crlf = "\r\n"

type Emailer struct {
	templates *template.Template
	storage   fiber.Storage
}

func init() {
	viper.SetDefault("smtp_host", "localhost")
	viper.SetDefault("smtp_port", 25)
	viper.SetDefault("smtp_tls", "off")
	viper.SetDefault("email_prefix", "mokey")
	viper.SetDefault("email_link_base", "http://localhost")
	viper.SetDefault("email_from", "helpdesk@example.com")
}

func NewEmailer(storage fiber.Storage) (*Emailer, error) {
	tmpl := template.New("")

	for _, ext := range []string{"txt", "html"} {
		tmpl, err := tmpl.ParseFS(templateFiles, "templates/email/*."+ext)
		if err != nil {
			return nil, err
		}

		localTemplatePath := filepath.Join(viper.GetString("templates_dir"), "email/*."+ext)
		localTemplates, err := filepath.Glob(localTemplatePath)
		if err != nil {
			return nil, err
		}

		if len(localTemplates) > 0 {
			tmpl, err = tmpl.ParseGlob(localTemplatePath)
			if err != nil {
				return nil, err
			}
		}
	}

	return &Emailer{storage: storage, templates: tmpl}, nil
}

func (e *Emailer) SendPasswordResetEmail(user *ipa.User, userAgent string) error {
	token, err := NewToken(user.Username, user.Email, e.storage)
	if err != nil {
		return err
	}

	vars := map[string]interface{}{
		"link": fmt.Sprintf("%s/auth/resetpw/%s", viper.GetString("email_link_base"), token),
	}

	err = e.sendEmail(user, userAgent, "Please reset your password", "password-reset", vars)
	if err != nil {
		return err
	}

	return nil
}

func (e *Emailer) SendAccountVerifyEmail(user *ipa.User, userAgent string) error {
	token, err := NewToken(user.Username, user.Email, e.storage)
	if err != nil {
		return err
	}

	vars := map[string]interface{}{
		"link": fmt.Sprintf("%s/auth/verify/%s", viper.GetString("email_link_base"), token),
	}

	err = e.sendEmail(user, userAgent, "Verify your email", "account-verify", vars)
	if err != nil {
		return err
	}

	return nil
}

func (e *Emailer) quotedBody(body []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := quotedprintable.NewWriter(&buf)
	_, err := w.Write(body)
	if err != nil {
		return nil, err
	}

	err = w.Close()
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (e *Emailer) sendEmail(user *ipa.User, userAgent, subject, tmpl string, data map[string]interface{}) error {
	log.WithFields(log.Fields{
		"email":    user.Email,
		"username": user.Username,
	}).Info("Sending email to user")

	if data == nil {
		data = make(map[string]interface{})
	}

	ua := useragent.Parse(userAgent)

	data["os"] = ua.OS
	data["browser"] = ua.Name
	data["name"] = user.First
	data["date"] = time.Now()
	data["contact"] = viper.GetString("email_from")
	data["sig"] = viper.GetString("email_sig")
	data["prefix"] = viper.GetString("email_prefix")
	data["email_link_base"] = viper.GetString("email_link_base")

	var text bytes.Buffer
	err := e.templates.ExecuteTemplate(&text, tmpl+".txt", data)
	if err != nil {
		return err
	}

	txtBody, err := e.quotedBody(text.Bytes())
	if err != nil {
		return err
	}

	var html bytes.Buffer
	err = e.templates.ExecuteTemplate(&html, tmpl+".html", data)
	if err != nil {
		return err
	}

	htmlBody, err := e.quotedBody(html.Bytes())
	if err != nil {
		return err
	}

	header := make(textproto.MIMEHeader)
	header.Set("Mime-Version", "1.0")
	header.Set("Date", time.Now().Format(time.RFC1123Z))
	header.Set("To", user.Email)
	header.Set("Subject", fmt.Sprintf("[%s] %s", viper.GetString("email_prefix"), subject))
	header.Set("From", viper.GetString("email_from"))

	var multipartBody bytes.Buffer
	mp := multipart.NewWriter(&multipartBody)
	header.Set("Content-Type", fmt.Sprintf("multipart/alternative;%s boundary=%s", crlf, mp.Boundary()))

	txtPart, err := mp.CreatePart(textproto.MIMEHeader(
		map[string][]string{
			"Content-Type":              []string{"text/plain; charset=utf-8"},
			"Content-Transfer-Encoding": []string{"quoted-printable"},
		}))
	if err != nil {
		return err
	}

	_, err = txtPart.Write(txtBody)
	if err != nil {
		return err
	}

	htmlPart, err := mp.CreatePart(textproto.MIMEHeader(
		map[string][]string{
			"Content-Type":              []string{"text/html; charset=utf-8"},
			"Content-Transfer-Encoding": []string{"quoted-printable"},
		}))
	if err != nil {
		return err
	}

	_, err = htmlPart.Write(htmlBody)
	if err != nil {
		return err
	}

	err = mp.Close()
	if err != nil {
		return err
	}

	smtpHostPort := fmt.Sprintf("%s:%d", viper.GetString("smtp_host"), viper.GetInt("smtp_port"))
	var conn net.Conn
	tlsMode := viper.GetString("smtp_tls")

	switch tlsMode {
	case "on":
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         viper.GetString("smtp_host"),
		}
		conn, err = tls.Dial("tcp", smtpHostPort, tlsConfig)
	case "off", "starttls":
		conn, err = net.Dial("tcp", smtpHostPort)
	default:
		return fmt.Errorf("invalid config value for smtp_tls: %s", tlsMode)
	}

	if err != nil {
		return err
	}

	c, err := smtp.NewClient(conn, viper.GetString("smtp_host"))
	if err != nil {
		return err
	}
	defer c.Close()

	if tlsMode == "starttls" {
		err := c.StartTLS(&tls.Config{
			ServerName: viper.GetString("smtp_host"),
		})
		if err != nil {
			return err
		}
	}

	if viper.IsSet("smtp_username") && viper.IsSet("smtp_password") {
		auth := smtp.PlainAuth("", viper.GetString("smtp_username"), viper.GetString("smtp_password"), viper.GetString("smtp_host"))
		if err = c.Auth(auth); err != nil {
			log.Error(err)
			return err
		}
	}
	if err = c.Mail(viper.GetString("email_from")); err != nil {
		log.Error(err)
		return err
	}
	if err = c.Rcpt(user.Email); err != nil {
		log.Error(err)
		return err
	}

	wc, err := c.Data()
	if err != nil {
		return err
	}
	defer wc.Close()

	var buf bytes.Buffer
	for k, vv := range header {
		for _, v := range vv {
			fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(&buf, "\r\n")

	if _, err = buf.WriteTo(wc); err != nil {
		return err
	}
	if _, err = wc.Write(multipartBody.Bytes()); err != nil {
		return err
	}

	return nil
}