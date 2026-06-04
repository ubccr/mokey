// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/gofiber/fiber/v2"
	"github.com/mileusna/useragent"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	ipa "github.com/ubccr/goipa"
)

const crlf = "\r\n"

type Emailer struct {
	templates *template.Template
	storage   fiber.Storage
}

func BaseURL(ctx *fiber.Ctx) string {
	baseURL := viper.GetString("email.base_url")
	if baseURL == "" {
		baseURL = ctx.BaseURL()
	}

	return baseURL
}

func NewEmailer(storage fiber.Storage) (*Emailer, error) {
	tmpl := template.New("")
	tmpl.Funcs(funcMap)

	for _, ext := range []string{"txt", "html"} {
		tmpl, err := tmpl.ParseFS(templateFiles, "templates/email/*."+ext)
		if err != nil {
			return nil, err
		}

		localTemplatePath := filepath.Join(viper.GetString("site.templates_dir"), "email/*."+ext)
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

func (e *Emailer) SendPasswordResetEmail(user *ipa.User, ctx *fiber.Ctx) error {
	token, err := NewToken(user.Username, user.Email, TokenPasswordReset, e.storage)
	if err != nil {
		return err
	}

	vars := map[string]interface{}{
		"link":         fmt.Sprintf("%s/auth/resetpw/%s", BaseURL(ctx), token),
		"link_expires": strings.TrimSpace(humanize.RelTime(time.Now(), time.Now().Add(time.Duration(viper.GetInt("email.token_max_age"))*time.Second), "", "")),
	}

	return e.sendEmail(user, ctx, Translate("", "email_template.password_reset_subject"), "password-reset", vars)
}

func (e *Emailer) SendAccountVerifyEmail(user *ipa.User, ctx *fiber.Ctx) error {
	token, err := NewToken(user.Username, user.Email, TokenAccountVerify, e.storage)
	if err != nil {
		return err
	}

	vars := map[string]interface{}{
		"link":         fmt.Sprintf("%s/auth/verify/%s", BaseURL(ctx), token),
		"link_expires": strings.TrimSpace(humanize.RelTime(time.Now(), time.Now().Add(time.Duration(viper.GetInt("email.token_max_age"))*time.Second), "", "")),
	}

	return e.sendEmail(user, ctx, Translate("", "email_template.account_verify_subject"), "account-verify", vars)
}

func (e *Emailer) SendWelcomeEmail(user *ipa.User, ctx *fiber.Ctx) error {
	vars := map[string]interface{}{
		"getting_started_url": viper.GetString("site.getting_started_url"),
	}

	subject := Translate("", "email_template.welcome_subject") + " " + viper.GetString("site.name")

	return e.sendEmail(user, ctx, subject, "welcome", vars)

}

func (e *Emailer) SendMFAChangedEmail(enabled bool, user *ipa.User, ctx *fiber.Ctx) error {
	var verbKey string
	if enabled {
		verbKey = "email_template.two_factor_auth_enabled"
	} else {
		verbKey = "email_template.two_factor_auth_disabled"
	}

	verb := Translate("", verbKey)
	event := Translate("", "email_template.two_factor_auth_event") + verb

	vars := map[string]interface{}{
		"event": event,
	}

	return e.sendEmail(user, ctx, event, "account-updated", vars)
}

func (e Emailer) SendSSHKeyUpdatedEmail(added bool, user *ipa.User, ctx *fiber.Ctx) error {
	var verbKey string
	if added {
		verbKey = "email_template.ssh_key_added"
	} else {
		verbKey = "email_template.ssh_key_removed"
	}

	verb := Translate("", verbKey)
	event := Translate("", "email_template.ssh_key_event") + verb

	vars := map[string]interface{}{
		"event": event,
	}
	return e.sendEmail(user, ctx, event, "account-updated", vars)
}

func (e *Emailer) SendOTPTokenUpdatedEmail(added bool, user *ipa.User, ctx *fiber.Ctx) error {
	var verbKey string
	if added {
		verbKey = "email_template.otp_token_added"
	} else {
		verbKey = "email_template.otp_token_removed"
	}

	verb := Translate("", verbKey)
	event := Translate("", "email_template.otp_token_event") + verb

	vars := map[string]interface{}{
		"event": event,
	}

	return e.sendEmail(user, ctx, event, "account-updated", vars)
}

func (e *Emailer) SendPasswordChangedEmail(user *ipa.User, ctx *fiber.Ctx) error {
	event := Translate("", "email_template.password_changed_event")

	vars := map[string]interface{}{
		"event": event,
	}

	return e.sendEmail(user, ctx, Translate("", "email_template.account_updated_subject"), "account-updated", vars)
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

func (e *Emailer) sendEmail(user *ipa.User, ctx *fiber.Ctx, subject, tmpl string, data map[string]interface{}) error {
	log.WithFields(log.Fields{
		"email":    user.Email,
		"username": user.Username,
	}).Debug("Sending email to user")

	if data == nil {
		data = make(map[string]interface{})
	}

	ua := useragent.Parse(ctx.Get(fiber.HeaderUserAgent))

	data["os"] = ua.OS
	data["browser"] = ua.Name
	data["user"] = user
	data["date"] = time.Now()
	data["contact"] = viper.GetString("email.from")
	data["sig"] = viper.GetString("email.signature")
	data["site_name"] = viper.GetString("site.name")
	data["help_url"] = viper.GetString("site.help_url")
	data["homepage"] = viper.GetString("site.homepage")
	data["base_url"] = BaseURL(ctx)

	// Ensure the "lang" key exists in the data map
	defaultLang := "en"
	if viper.IsSet("site.default_language") {
		defaultLang = viper.GetString("site.default_language")
	}

	if lang, exists := data["lang"]; !exists || lang == "" {
		log.Printf("DEBUG: 'lang' key not found or empty, using default language '%s'", defaultLang)
		data["lang"] = defaultLang
	} else {
		log.Debugf("DEBUG: Using provided 'lang' key with value: %v", lang)
	}

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

	// Determine logo path
	logoPath := viper.GetString("email.logo_path")
	if logoPath == "" {
		logoPath = filepath.Join(viper.GetString("site.templates_dir"), "static/images/logo.png")
	}
	if _, err := os.Stat(logoPath); os.IsNotExist(err) {
		logoPath = "/etc/mokey/templates/static/images/logo.png"
	}

	// Load logo file
	var logoData []byte
	var logoContentType string
	if logoData, err = ioutil.ReadFile(logoPath); err == nil {
		logoContentType = "image/png"
		log.Debugf("Loaded logo from %s (%d bytes)", logoPath, len(logoData))
	} else {
		log.Warnf("Failed to load logo from %s: %v", logoPath, err)
		logoData = nil
	}

	header := make(textproto.MIMEHeader)
	header.Set("Mime-Version", "1.0")
	header.Set("Date", time.Now().Format(time.RFC1123Z))
	header.Set("To", user.Email)
	header.Set("Subject", fmt.Sprintf("[%s] %s", viper.GetString("site.name"), subject))
	header.Set("From", viper.GetString("email.from"))

	// Manually build multipart/related structure with nested multipart/alternative
	var multipartBody bytes.Buffer
	outerBoundary := "related-" + fmt.Sprintf("%x", time.Now().UnixNano())
	innerBoundary := "alternative-" + fmt.Sprintf("%x", time.Now().UnixNano())

	header.Set("Content-Type", fmt.Sprintf("multipart/related; boundary=%s", outerBoundary))

	// Start outer multipart
	multipartBody.WriteString("--" + outerBoundary + "\r\n")

	// Start inner multipart/alternative
	multipartBody.WriteString("Content-Type: multipart/alternative; boundary=" + innerBoundary + "\r\n")
	multipartBody.WriteString("\r\n")

	// Text/plain part
	multipartBody.WriteString("--" + innerBoundary + "\r\n")
	multipartBody.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	multipartBody.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	multipartBody.WriteString("\r\n")
	multipartBody.Write(txtBody)
	multipartBody.WriteString("\r\n")

	// Text/html part
	multipartBody.WriteString("--" + innerBoundary + "\r\n")
	multipartBody.WriteString("Content-Type: text/html; charset=utf-8\r\n")
	multipartBody.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	multipartBody.WriteString("\r\n")
	multipartBody.Write(htmlBody)
	multipartBody.WriteString("\r\n")

	// Close inner multipart/alternative
	multipartBody.WriteString("--" + innerBoundary + "--\r\n")
	multipartBody.WriteString("\r\n")

	// Add logo as inline image attachment
	if logoData != nil {
		multipartBody.WriteString("--" + outerBoundary + "\r\n")
		multipartBody.WriteString("Content-Type: " + logoContentType + "\r\n")
		multipartBody.WriteString("Content-Transfer-Encoding: base64\r\n")
		multipartBody.WriteString("Content-ID: <email_logo>\r\n")
		multipartBody.WriteString("Content-Disposition: inline; filename=\"logo.png\"\r\n")
		multipartBody.WriteString("\r\n")

		encodedLogo := make([]byte, base64.StdEncoding.EncodedLen(len(logoData)))
		base64.StdEncoding.Encode(encodedLogo, logoData)
		multipartBody.Write(encodedLogo)
		multipartBody.WriteString("\r\n")
	}

	// Close outer multipart
	multipartBody.WriteString("--" + outerBoundary + "--\r\n")

	smtpHostPort := fmt.Sprintf("%s:%d", viper.GetString("email.smtp_host"), viper.GetInt("email.smtp_port"))
	var conn net.Conn
	tlsMode := viper.GetString("email.smtp_tls")

	switch tlsMode {
	case "on":
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         viper.GetString("email.smtp_host"),
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

	c, err := smtp.NewClient(conn, viper.GetString("email.smtp_host"))
	if err != nil {
		return err
	}
	defer c.Close()

	if tlsMode == "starttls" {
		err := c.StartTLS(&tls.Config{
			ServerName: viper.GetString("email.smtp_host"),
		})
		if err != nil {
			return err
		}
	}

	if viper.IsSet("email.smtp_username") && viper.IsSet("email.smtp_password") {
		auth := smtp.PlainAuth("", viper.GetString("email.smtp_username"), viper.GetString("email.smtp_password"), viper.GetString("email.smtp_host"))
		if err = c.Auth(auth); err != nil {
			log.Error(err)
			return err
		}
	}

	if err = c.Mail(viper.GetString("email.from")); err != nil {
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
