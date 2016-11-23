// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package app

import (
	"bytes"
	"crypto"
	"fmt"
	"mime/multipart"
	"mime/quotedprintable"
	"net/smtp"
	"net/textproto"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

func quotedBody(body []byte) ([]byte, error) {
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

func sign(qtext []byte, header textproto.MIMEHeader) ([]byte, error) {
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

func (a *AppContext) SendEmail(email, subject, template string, data map[string]interface{}) error {
	log.WithFields(log.Fields{
		"email": email,
	}).Info("Sending email to user")

	if data == nil {
		data = make(map[string]interface{})
	}

	data["date"] = time.Now()
	data["contact"] = viper.GetString("email_from")
	data["sig"] = viper.GetString("email_sig")

	t := a.emails[template]
	var text bytes.Buffer
	err := t.ExecuteTemplate(&text, template, data)
	if err != nil {
		return err
	}

	qtext, err := quotedBody(text.Bytes())
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
		sig, err := sign(qtext, mhead)
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
