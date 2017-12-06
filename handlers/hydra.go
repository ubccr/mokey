// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/context"
	"github.com/gorilla/csrf"
	"github.com/ory/hydra/sdk"
	log "github.com/sirupsen/logrus"
	"github.com/ubccr/mokey/app"
	"github.com/ubccr/mokey/model"
)

func ConsentHandler(ctx *app.AppContext) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ctx.HydraClient == nil {
			log.Info("Hydra is not configured")
			ctx.RenderNotFound(w)
			return
		}

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

			if contextKey := context.Get(r, app.ContextKeyApi); contextKey != nil {
				key := contextKey.(*model.ApiKey)

				log.WithFields(log.Fields{
					"user":      key.UserName,
					"client_id": key.ClientID,
					"audience":  claims.Audience,
				}).Info("Api consent request")

				// Check key matches client
				if key.ClientID != claims.Audience {
					log.WithFields(log.Fields{
						"key":       key.Key,
						"user":      key.UserName,
						"client_id": key.ClientID,
						"audience":  claims.Audience,
					}).Error("Claims audience does not match api key")
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				// Check key matches scopes
				if key.Scopes != strings.Join(claims.RequestedScopes, ",") {
					log.WithFields(log.Fields{
						"key":           key.Key,
						"user":          key.UserName,
						"key_scopes":    key.Scopes,
						"claims_scopes": claims.RequestedScopes,
					}).Error("Claims scopes does not match api key")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
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

		if strings.Contains(r.Header.Get("Accept"), "application/json") {
			data := map[string]string{
				app.CSRFFieldName: csrf.Token(r),
				"audience":        claims.Audience,
				"scopes":          strings.Join(claims.RequestedScopes, ","),
				"challenge":       challenge}

			payload, err := json.Marshal(data)
			if err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("Failed to marshal json payload for consent")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(payload)
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
