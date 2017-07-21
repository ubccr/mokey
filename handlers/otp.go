// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package handlers

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"net/http"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/csrf"
	"github.com/pquerna/otp"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/app"
)

func TwoFactorHandler(ctx *app.AppContext) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := ctx.GetUser(r)
		if user == nil {
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		session, err := ctx.GetSession(r)
		if err != nil {
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		message := ""

		if r.Method == "POST" {
			// These operations require admin privs. TODO: should we make this
			// configurable?
			c := app.NewIpaClient(true)
			action := r.FormValue("action")
			if action == "remove" {
				// Remove any auth types which will fall back to FreeIPA global default.
				err := c.SetAuthTypes(string(user.Uid), nil)
				if err == nil {
					user.AuthTypes = []string{}
				} else {
					log.WithFields(log.Fields{
						"user":  string(user.Uid),
						"error": err,
					}).Error("failed to reset auth types to default")
					message = "Failed to disable TOTP. Please contact your administrator"
				}
			} else if action == "enable" {
				err := c.SetAuthTypes(string(user.Uid), []string{"otp"})
				if err == nil {
					user.AuthTypes = []string{"otp"}
				} else {
					log.WithFields(log.Fields{
						"user":  string(user.Uid),
						"error": err,
					}).Error("failed to set auth types to otp")
					message = "Failed to enable TOTP. Please contact your administrator"
				}

				sid := session.Values[app.CookieKeySID]
				c.SetSession(sid.(string))
				tokens, err := c.FetchOTPTokens(string(user.Uid))
				if err != nil {
					log.WithFields(log.Fields{
						"user":  string(user.Uid),
						"error": err,
					}).Error("failed to fetch OTP tokens")
					ctx.RenderError(w, http.StatusInternalServerError)
					return
				}
				if len(tokens) == 0 {
					addNewToken(ctx, w, r)
					return
				}
			}
		}

		vars := map[string]interface{}{
			"flashes":        session.Flashes(),
			"otpenabled":     user.OTPOnly(),
			csrf.TemplateTag: csrf.TemplateField(r),
			"message":        message,
			"user":           user}

		session.Save(r, w)
		ctx.RenderTemplate(w, "2fa.html", vars)
	})
}

func OTPTokensHandler(ctx *app.AppContext) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := ctx.GetUser(r)
		if user == nil {
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		session, err := ctx.GetSession(r)
		if err != nil {
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		sid := session.Values[app.CookieKeySID]
		c := app.NewIpaClient(false)
		c.SetSession(sid.(string))

		message := ""

		if r.Method == "POST" {
			action := r.FormValue("action")
			uuid := r.FormValue("uuid")
			log.WithFields(log.Fields{
				"user":   string(user.Uid),
				"uuid":   uuid,
				"action": action,
			}).Info("otptokens action")

			if action == "delete" && len(uuid) > 0 {
				err := c.RemoveOTPToken(uuid)
				if err != nil {
					log.WithFields(log.Fields{
						"user":  string(user.Uid),
						"uuid":  uuid,
						"error": err,
					}).Error("failed to remove OTP Token")

					// Raised when there's an operations error
					if ierr, ok := err.(*ipa.IpaError); ok && ierr.Code == 4203 && strings.Contains(ierr.Message, "last active token") {
						message = "Can't delete last active token"
					} else {
						message = "Failed to remove OTP Token"
					}
				}
			} else if action == "enable" && len(uuid) > 0 {
				err := c.EnableOTPToken(uuid)
				if err != nil {
					log.WithFields(log.Fields{
						"user":  string(user.Uid),
						"uuid":  uuid,
						"error": err,
					}).Error("failed to enable OTP Token")
					message = "Failed to enable OTP Token"
				}
			} else if action == "disable" && len(uuid) > 0 {
				err := c.DisableOTPToken(uuid)
				if err != nil {
					log.WithFields(log.Fields{
						"user":  string(user.Uid),
						"uuid":  uuid,
						"error": err,
					}).Error("failed to disable OTP Token")
					message = "Failed to disable OTP Token"
				}
			} else if action == "add" {
				addNewToken(ctx, w, r)
				return
			}
		}

		tokens, err := c.FetchOTPTokens(string(user.Uid))
		if err != nil {
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		vars := map[string]interface{}{
			"flashes":        session.Flashes(),
			csrf.TemplateTag: csrf.TemplateField(r),
			"message":        message,
			"otptokens":      tokens,
			"user":           user}

		session.Save(r, w)
		ctx.RenderTemplate(w, "otp-tokens.html", vars)
	})
}

func addNewToken(ctx *app.AppContext, w http.ResponseWriter, r *http.Request) {
	user := ctx.GetUser(r)
	if user == nil {
		ctx.RenderError(w, http.StatusInternalServerError)
		return
	}

	session, err := ctx.GetSession(r)
	if err != nil {
		ctx.RenderError(w, http.StatusInternalServerError)
		return
	}

	sid := session.Values[app.CookieKeySID]
	c := app.NewIpaClient(false)
	c.SetSession(sid.(string))

	otptoken, err := c.AddTOTPToken(string(user.Uid), ipa.AlgorithmSHA1, ipa.DigitsSix, 30)
	if err != nil {
		log.WithFields(log.Fields{
			"user":  string(user.Uid),
			"error": err,
		}).Error("Failed to create TOTP")
		ctx.RenderError(w, http.StatusInternalServerError)
		return
	}

	otpdata, err := QRCode(otptoken)
	if err != nil {
		log.WithFields(log.Fields{
			"user":  string(user.Uid),
			"error": err,
		}).Error("failed to render TOTP token as QRCode image")
		ctx.RenderError(w, http.StatusInternalServerError)
		return
	}

	vars := map[string]interface{}{
		"otpdata":  otpdata,
		"otptoken": otptoken,
		"user":     user}

	ctx.RenderTemplate(w, "verify-totp.html", vars)
}

func RemoveAllOTPTokens(uid, sid string) error {
	c := app.NewIpaClient(false)
	c.SetSession(sid)

	tokens, err := c.FetchOTPTokens(uid)
	if err != nil {
		return err
	}

	for _, t := range tokens {
		err = c.RemoveOTPToken(string(t.UUID))
		if err != nil {
			return err
		}
	}

	return nil
}

func QRCode(otptoken *ipa.OTPToken) (string, error) {
	if otptoken == nil {
		return "", nil
	}

	key, err := otp.NewKeyFromURL(otptoken.URI)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	img, err := key.Image(250, 250)
	if err != nil {
		return "", err
	}

	png.Encode(&buf, img)
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
