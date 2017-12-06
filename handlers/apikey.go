// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package handlers

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/gorilla/csrf"
	log "github.com/sirupsen/logrus"
	"github.com/ubccr/mokey/app"
	"github.com/ubccr/mokey/model"
)

func ApiKeyHandler(ctx *app.AppContext) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(ctx.ApiClients) == 0 {
			log.Info("No api key clients configured")
			ctx.RenderNotFound(w)
			return
		}

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
			action := r.FormValue("action")
			clientID := r.FormValue("client_id")

			if clientID != "" && action == "remove" {
				err = removeApiKey(ctx, string(user.Uid), clientID)

				if err == nil {
					message = "Api Key Deleted"
				} else {
					message = err.Error()
				}
			} else if clientID != "" && action == "enable" {
				secret, client, err := enableApiKey(ctx, string(user.Uid), clientID)

				if err == nil {
					vars := map[string]interface{}{
						"client": client,
						"secret": secret,
						"user":   user}

					ctx.RenderTemplate(w, "apikey-show.html", vars)
					return
				}

				message = err.Error()
			}
		}

		keys, err := model.FetchApiKeys(ctx.DB, string(user.Uid))
		if err != nil && err != sql.ErrNoRows {
			log.WithFields(log.Fields{
				"uid":   string(user.Uid),
				"error": err,
			}).Error("Failed to fetch api keys")
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		keyMap := make(map[string]*model.ApiKey)
		for _, k := range keys {
			keyMap[k.ClientID] = k
		}

		vars := map[string]interface{}{
			"flashes":        session.Flashes(),
			csrf.TemplateTag: csrf.TemplateField(r),
			"apiClients":     ctx.ApiClients,
			"message":        message,
			"keys":           keyMap,
			"user":           user}

		session.Save(r, w)
		ctx.RenderTemplate(w, "apikey.html", vars)
	})
}

func removeApiKey(ctx *app.AppContext, user, clientID string) error {
	err := model.DestroyApiKey(ctx.DB, user, clientID)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":   user,
			"error": err,
		}).Error("Failed to remove api key")
		return errors.New("Failed to remove api key")
	}

	return nil
}

func enableApiKey(ctx *app.AppContext, user, clientID string) (string, *app.ApiKeyClient, error) {
	client, ok := ctx.ApiClients[clientID]

	if !ok {
		log.WithFields(log.Fields{
			"uid":      user,
			"clientID": client.ClientID,
		}).Error("Invalid client ID")
		return "", nil, errors.New("Invalid client id")
	}

	_, secret, err := model.CreateApiKey(ctx.DB, user, client.ClientID, client.Scopes)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":      user,
			"clientID": client.ClientID,
			"error":    err,
		}).Error("Failed to create new api key")
		return "", nil, errors.New("Fatal system error. Please contact your administrator")
	}

	return secret, client, nil
}
