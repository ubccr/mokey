// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package handlers

import (
	"net/http"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/ory/hydra/sdk"
	log "github.com/sirupsen/logrus"
	"github.com/ubccr/mokey/app"
)

func ConsentHandler(ctx *app.AppContext) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := ctx.GetUser(r)
		if user == nil {
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		// Get the challenge from the query.
		challenge := r.URL.Query().Get("challenge")
		if challenge == "" {
			log.WithFields(log.Fields{
				"user": string(user.Uid),
			}).Error("Consent endpoint was called without a consent challenge")
			ctx.RenderError(w, http.StatusBadRequest)
			return
		}

		// Verify the challenge and extract the challenge claims.
		claims, err := ctx.HydraClient.Consent.VerifyChallenge(challenge)
		if err != nil {
			log.WithFields(log.Fields{
				"user": string(user.Uid),
			}).Error("The consent challenge could not be verified")
			ctx.RenderError(w, http.StatusBadRequest)
			return
		}

		if r.Method == "POST" {

			if err := r.ParseForm(); err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("Failed to parse form")
				ctx.RenderError(w, http.StatusBadRequest)
				return
			}

			grantedScopes := r.PostForm["scope"]
			if grantedScopes == nil {
				grantedScopes = []string{}
			}

			// Generate the challenge response.
			redirectUrl, err := ctx.HydraClient.Consent.GenerateResponse(&sdk.ResponseRequest{
				// We need to include the original challenge.
				Challenge: challenge,

				// The subject is a string, usually the user id.
				Subject: string(user.Uid),

				// The scopes our user granted.
				Scopes: grantedScopes,

				// Data that will be available on the token introspection and warden endpoints.
				AccessTokenExtra: struct {
					UID    string `json:"uid"`
					First  string `json:"first"`
					Last   string `json:"last"`
					Email  string `json:"email"`
					Groups string `json:"groups"`
				}{
					UID:    string(user.Uid),
					First:  string(user.First),
					Last:   string(user.Last),
					Groups: strings.Join(user.Groups, ";"),
					Email:  string(user.Email)},

				// If we issue an ID token, we can set extra data for that id token here.
				IDTokenExtra: struct {
					UID    string `json:"uid"`
					First  string `json:"first"`
					Last   string `json:"last"`
					Email  string `json:"email"`
					Groups string `json:"groups"`
				}{
					UID:    string(user.Uid),
					First:  string(user.First),
					Last:   string(user.Last),
					Groups: strings.Join(user.Groups, ";"),
					Email:  string(user.Email)},
			})

			if err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("Could not sign the consent challenge")
				ctx.RenderError(w, http.StatusBadRequest)
				return
			}

			log.WithFields(log.Fields{
				"redirectURL": redirectUrl,
			}).Info("Consent challenge signed successfully")

			http.Redirect(w, r, redirectUrl, http.StatusFound)
			return
		}

		vars := map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"claims":         claims,
			"challenge":      challenge,
			"firstName":      user.First}

		ctx.RenderTemplate(w, "consent.html", vars)
	})
}
