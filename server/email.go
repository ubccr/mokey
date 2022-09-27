// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"fmt"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"text/template"
	"time"

	"github.com/mileusna/useragent"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/model"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

const crlf = "\r\n"

type Emailer struct {
	templates *template.Template
}

func init() {
	viper.SetDefault("pgp_sign", false)
	viper.SetDefault("smtp_host", "localhost")
	viper.SetDefault("smtp_port", 25)
	viper.SetDefault("smtp_tls", "off")
	viper.SetDefault("email_prefix", "mokey")
	viper.SetDefault("email_link_base", "http://localhost")
	viper.SetDefault("email_from", "helpdesk@example.com")
}

func NewEmailer() (*Emailer, error) {
	tmpl := template.New("")
	tmpl, err := tmpl.ParseFS(templateFiles, "templates/email/email-*.*")
	if err != nil {
		return nil, err
	}

	localTemplatePath := filepath.Join(viper.GetString("templates_dir"), "email/email-*.*")
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

	return &Emailer{templates: tmpl}, nil
}

func (e *Emailer) SendResetPasswordEmail(uid, email string) error {
	token, err := model.NewToken(uid, email, viper.GetUint32("token_max_age"))
	if err != nil {
		return err
	}

	vars := map[string]interface{}{
		"link": fmt.Sprintf("%s/auth/resetpw/%s", viper.GetString("email_link_base"), token),
	}

	err = e.sendEmail(email, fmt.Sprintf("[%s] Please reset your password", viper.GetString("email_prefix")), "reset-password.txt", vars)
	if err != nil {
		return err
	}

	return nil
}

func (e *Emailer) SendVerifyAccountEmail(user *ipa.User, userAgent string) error {
	token, err := model.NewToken(user.Username, user.Email, viper.GetUint32("token_max_age"))
	if err != nil {
		return err
	}

	ua := useragent.Parse(userAgent)

	vars := map[string]interface{}{
		"name":    user.First,
		"os":      ua.OS,
		"browser": ua.Name,
		"link":    fmt.Sprintf("%s/auth/verify/%s", viper.GetString("email_link_base"), token),
	}

	err = e.sendEmail(user.Email, fmt.Sprintf("[%s] Verify your email", viper.GetString("email_prefix")), "email-setup-account", vars)
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

func (e *Emailer) sign(qtext []byte, header textproto.MIMEHeader) ([]byte, error) {
	var buf bytes.Buffer

	for k, vv := range header {
		for _, v := range vv {
			fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(&buf, "\r\n")
	_, err := buf.Write(qtext)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(viper.GetString("pgp_key"))
	if err != nil {
		return nil, err
	}

	keyring, err := openpgp.ReadArmoredKeyRing(file)
	if err != nil {
		return nil, err
	}

	signingKey := keyring[0]

	if signingKey.PrivateKey.Encrypted {
		err = signingKey.PrivateKey.Decrypt([]byte(viper.GetString("pgp_passphrase")))
		if err != nil {
			return nil, err
		}
	}

	var sig bytes.Buffer
	err = openpgp.ArmoredDetachSign(&sig, signingKey, &buf, &packet.Config{DefaultHash: crypto.SHA256})
	if err != nil {
		return nil, err
	}

	return sig.Bytes(), nil
}

func (e *Emailer) sendEmail(email, subject, tmpl string, data map[string]interface{}) error {
	log.WithFields(log.Fields{
		"email": email,
	}).Info("Sending email to user")

	if data == nil {
		data = make(map[string]interface{})
	}

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
	header.Set("To", email)
	header.Set("Subject", subject)
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
	if err = c.Rcpt(email); err != nil {
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
