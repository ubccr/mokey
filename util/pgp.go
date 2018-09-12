// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package util

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"fmt"
	"mime/multipart"
	"mime/quotedprintable"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"text/template"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/mokey/model"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

const (
	ResetSalt  = "resetpw"
	VerifySalt = "acctsetup"
)

type Emailer struct {
	db        model.Datastore
	templates map[string]*template.Template
}

func init() {
	viper.SetDefault("pgp_sign", false)
	viper.SetDefault("smtp_host", "localhost")
	viper.SetDefault("smtp_port", 25)
	viper.SetDefault("smtp_starttls", false)
	viper.SetDefault("email_prefix", "mokey")
	viper.SetDefault("email_link_base", "http://localhost")
	viper.SetDefault("email_from", "helpdesk@example.com")
}

func NewEmailer(db model.Datastore) (*Emailer, error) {
	tmpldir := GetTemplateDir()

	tmpls, err := filepath.Glob(tmpldir + "/email/*.txt")
	if err != nil {
		return nil, err
	}

	templates := make(map[string]*template.Template)
	for _, t := range tmpls {
		base := filepath.Base(t)
		templates[base] = template.Must(template.New(base).ParseFiles(t))
	}

	return &Emailer{db: db, templates: templates}, nil
}

func (e *Emailer) SendResetPasswordEmail(uid, email string) error {
	token, err := e.db.CreateToken(uid, email)
	if err != nil {
		return err
	}

	vars := map[string]interface{}{
		"link": fmt.Sprintf("%s/auth/resetpw/%s", viper.GetString("email_link_base"), e.db.SignToken(ResetSalt, token.Token))}

	err = e.sendEmail(token.Email, fmt.Sprintf("[%s] Please reset your password", viper.GetString("email_prefix")), "reset-password.txt", vars)
	if err != nil {
		return err
	}

	return nil
}

func (e *Emailer) SendVerifyAccountEmail(uid, email string) error {
	token, err := e.db.CreateToken(uid, email)
	if err != nil {
		return err
	}

	vars := map[string]interface{}{
		"uid":  uid,
		"link": fmt.Sprintf("%s/auth/verify/%s", viper.GetString("email_link_base"), e.db.SignToken(VerifySalt, token.Token))}

	err = e.sendEmail(token.Email, fmt.Sprintf("[%s] Verify your email", viper.GetString("email_prefix")), "setup-account.txt", vars)
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

	if _, ok := e.templates[tmpl]; !ok {
		return fmt.Errorf("Failed to find email template: %s", tmpl)
	}

	var text bytes.Buffer
	err := e.templates[tmpl].ExecuteTemplate(&text, tmpl, data)
	if err != nil {
		return err
	}

	qtext, err := e.quotedBody(text.Bytes())
	if err != nil {
		return err
	}

	header := make(textproto.MIMEHeader)
	header.Set("Mime-Version", "1.0")
	header.Set("Date", time.Now().Format(time.RFC1123Z))
	header.Set("To", email)
	header.Set("Subject", subject)
	header.Set("From", viper.GetString("email_from"))
	header.Set("Content-Type", "text/plain; charset=UTF-8")
	header.Set("Content-Transfer-Encoding", "quoted-printable")

	body := qtext

	if viper.GetBool("pgp_sign") {
		header.Del("Content-Transfer-Encoding")

		mhead := make(textproto.MIMEHeader)
		mhead.Add("Content-Type", "text/plain; charset=UTF-8")
		mhead.Add("Content-Transfer-Encoding", "quoted-printable")
		sig, err := e.sign(qtext, mhead)
		if err != nil {
			return err
		}

		var multipartBody bytes.Buffer
		mp := multipart.NewWriter(&multipartBody)
		boundary := mp.Boundary()
		mw, err := mp.CreatePart(mhead)
		if err != nil {
			return err
		}
		_, err = mw.Write(qtext)
		if err != nil {
			return err
		}

		mw, err = mp.CreatePart(textproto.MIMEHeader(
			map[string][]string{
				"Content-Type": []string{"application/pgp-signature; name=signature.asc;"},
			}))
		if err != nil {
			return err
		}

		_, err = mw.Write(sig)
		if err != nil {
			return err
		}

		err = mp.Close()
		if err != nil {
			return err
		}

		header.Set("Content-Type", fmt.Sprintf(`multipart/signed; boundary="%s"; protocol="application/pgp-signature"; micalg="pgp-sha256"`, boundary))
		body = multipartBody.Bytes()
	}

	c, err := smtp.Dial(fmt.Sprintf("%s:%d", viper.GetString("smtp_host"), viper.GetInt("smtp_port")))
	if err != nil {
		return err
	}
	defer c.Close()

	if viper.GetBool("smtp_starttls") {
		err := c.StartTLS(&tls.Config{
			ServerName: viper.GetString("smtp_host"),
		})
		if err != nil {
			return err
		}
	}

	c.Mail(viper.GetString("email_from"))
	c.Rcpt(email)

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
	if _, err = wc.Write(body); err != nil {
		return err
	}

	return nil
}
