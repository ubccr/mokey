// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package handlers

import (
	"bytes"
	"image/png"
	"net/http"
	"strconv"

	log "github.com/Sirupsen/logrus"
	"github.com/justinas/nosurf"
	"github.com/pquerna/otp"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/app"
	"github.com/ubccr/mokey/model"
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
			sid := session.Values[app.CookieKeySID]
			action := r.FormValue("action")
			if action == "remove" {
				err = disableTOTP(ctx, user, sid.(string))

				if err == nil {
					message = "TOTP Disabled"
				} else {
					message = "Failed to disable TOTP. Please contact your administrator"
				}
			}
		}

		token, _ := model.FetchConfirmedOTPToken(ctx.Db, string(user.Uid))

		vars := map[string]interface{}{
			"flashes":   session.Flashes(),
			"totptoken": token,
			"token":     nosurf.Token(r),
			"message":   message,
			"user":      user}

		session.Save(r, w)
		ctx.RenderTemplate(w, "2fa.html", vars)
	})
}

func EnableTOTPHandler(ctx *app.AppContext) http.Handler {
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

		_, err = model.FetchConfirmedOTPToken(ctx.Db, string(user.Uid))
		if err == nil {
			session.AddFlash("TOTP Already Enabled")
			session.Save(r, w)
			http.Redirect(w, r, "/2fa", 302)
			return
		}

		_, err = model.FetchUnconfirmedOTPToken(ctx.Db, string(user.Uid))
		if err == nil {
			log.Info("User already has an uncofirmed TOTP")
			http.Redirect(w, r, "/2fa/verify", 302)
			return
		}

		sid := session.Values[app.CookieKeySID]
		c := app.NewIpaClient(false)
		c.SetSession(sid.(string))

		uri, err := c.AddTOTPToken(string(user.Uid), ipa.AlgorithmSHA1, ipa.DigitsSix, 30)
		if err != nil {
			if ierr, ok := err.(*ipa.IpaError); ok && ierr.Code == 4002 {
				// 4002 user already has a TOTP that mokey doesn't know about
				session.AddFlash("You already have a TOTP set in FreeIPA. Please contact your administrator or remove existing TOTP manually.")
				session.Save(r, w)
				http.Redirect(w, r, "/2fa", 302)
				return
			} else {
				log.WithFields(log.Fields{
					"user":  string(user.Uid),
					"error": err,
				}).Error("Failed to create TOTP")
				ctx.RenderError(w, http.StatusInternalServerError)
				return
			}
		}

		err = model.StoreOTPToken(ctx.Db, string(user.Uid), uri)
		if err != nil {
			log.WithFields(log.Fields{
				"user":  string(user.Uid),
				"error": err,
			}).Error("Failed to save TOTP to database")
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/2fa/verify", 302)
		return
	})
}

func VerifyTOTPHandler(ctx *app.AppContext) http.Handler {
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

		_, err = model.FetchConfirmedOTPToken(ctx.Db, string(user.Uid))
		if err == nil {
			session.AddFlash("TOTP Already Enabled")
			session.Save(r, w)
			http.Redirect(w, r, "/2fa", 302)
			return
		}

		token, err := model.FetchUnconfirmedOTPToken(ctx.Db, string(user.Uid))
		if err != nil {
			log.WithFields(log.Fields{
				"user":  string(user.Uid),
				"error": err,
			}).Error("Failed to fetch TOTP")
			ctx.RenderNotFound(w)
			return
		}

		message := ""
		if r.Method == "POST" {
			code := r.FormValue("code")
			if token.Validate(code) {
				err := model.ConfirmOTPToken(ctx.Db, string(user.Uid))
				if err != nil {
					log.WithFields(log.Fields{
						"user":  string(user.Uid),
						"error": err,
					}).Error("Failed to confirm TOTP")
					ctx.RenderError(w, http.StatusInternalServerError)
					return
				}

				session.AddFlash("TOTP Enabled Successfully")
				session.Save(r, w)
				http.Redirect(w, r, "/2fa", 302)
				return
			}

			message = "Invalid code. Try again"
		}

		vars := map[string]interface{}{
			"token":   nosurf.Token(r),
			"message": message,
			"user":    user}

		ctx.RenderTemplate(w, "verify-totp.html", vars)
	})
}

func disableTOTP(ctx *app.AppContext, user *ipa.UserRecord, sid string) error {
	c := app.NewIpaClient(false)
	c.SetSession(sid)

	err := c.RemoveOTPToken(string(user.Uid))
	if err != nil {
		if ierr, ok := err.(*ipa.IpaError); ok {
			// 4001 not found means user didn't have a token so we ignore
			if ierr.Code != 4001 {
				log.WithFields(log.Fields{
					"user":  string(user.Uid),
					"error": err,
				}).Error("Failed to remove TOTP from FreeIPA")
				return err
			}
		} else {
			log.WithFields(log.Fields{
				"user":  string(user.Uid),
				"error": err,
			}).Error("Failed to remove TOTP from FreeIPA")
			return err
		}
	}

	err = model.RemoveOTPToken(ctx.Db, string(user.Uid))
	if err != nil {
		log.WithFields(log.Fields{
			"user":  string(user.Uid),
			"error": err,
		}).Error("Failed to remove TOTP")
		return err
	}

	return nil
}

func QRCodeHandler(ctx *app.AppContext) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := ctx.GetUser(r)
		if user == nil {
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		token, err := model.FetchUnconfirmedOTPToken(ctx.Db, string(user.Uid))
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		key, err := otp.NewKeyFromURL(token.URI)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var buf bytes.Buffer
		img, err := key.Image(250, 250)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		png.Encode(&buf, img)

		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Content-Length", strconv.Itoa(len(buf.Bytes())))

		buf.WriteTo(w)
	})
}
