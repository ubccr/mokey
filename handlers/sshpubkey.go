// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package handlers

import (
	"errors"
	"io/ioutil"
	"net/http"
	"strconv"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/justinas/nosurf"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/app"
)

func SSHPubKeyHandler(ctx *app.AppContext) http.Handler {
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

		vars := map[string]interface{}{
			"flashes": session.Flashes(),
			"user":    user}

		session.Save(r, w)
		ctx.RenderTemplate(w, "ssh-pubkey.html", vars)
	})
}

func RemoveSSHPubKeyHandler(ctx *app.AppContext) http.Handler {
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

		index, _ := strconv.Atoi(mux.Vars(r)["index"])
		if index < 0 || index > len(user.SSHPubKeys) {
			log.WithFields(log.Fields{
				"user":  string(user.Uid),
				"index": index,
			}).Error("Invalid ssh pub key index")
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		pubKeys := make([]string, len(user.SSHPubKeys))
		copy(pubKeys, user.SSHPubKeys)

		// Remove key at index
		pubKeys = append(pubKeys[:index], pubKeys[index+1:]...)

		sid := session.Values[app.CookieKeySID]
		c := app.NewIpaClient(false)
		c.SetSession(sid.(string))

		newFps, err := c.UpdateSSHPubKeys(string(user.Uid), pubKeys)
		if err != nil {
			log.WithFields(log.Fields{
				"user":  string(user.Uid),
				"index": index,
				"error": err,
			}).Error("Failed to delete ssh pub key")
			ctx.RenderError(w, http.StatusInternalServerError)
			return
		}

		user.SSHPubKeys = pubKeys
		user.SSHPubKeyFps = newFps
		session.Values[app.CookieKeyUser] = user
		session.AddFlash("SSH Pub Key Deleted")
		session.Save(r, w)

		http.Redirect(w, r, "/sshpubkey", 302)
		return
	})
}

func addSSHPubKey(user *ipa.UserRecord, pubKey, sid string) error {
	if len(pubKey) == 0 {
		return errors.New("No ssh key provided. Please provide a valid ssh public key")
	}

	pubKeys := make([]string, len(user.SSHPubKeys))
	copy(pubKeys, user.SSHPubKeys)
	found := false
	for _, k := range pubKeys {
		if k == pubKey {
			found = true
		}
	}

	if found {
		return errors.New("ssh key already exists.")
	}

	pubKeys = append(pubKeys, pubKey)

	c := app.NewIpaClient(false)
	c.SetSession(sid)

	newFps, err := c.UpdateSSHPubKeys(string(user.Uid), pubKeys)
	if err != nil {
		if ierr, ok := err.(*ipa.IpaError); ok {
			// Raised when a parameter value fails a validation rule
			if ierr.Code == 3009 {
				return errors.New("Invalid ssh public key")
			}
		} else {
			log.WithFields(log.Fields{
				"error": err.Error(),
				"user":  string(user.Uid),
			}).Error("Ipa error when attempting to add new ssh public key")
			return errors.New("Fatal system error occured.")
		}
	}

	user.SSHPubKeys = pubKeys
	user.SSHPubKeyFps = newFps

	return nil
}

func NewSSHPubKeyHandler(ctx *app.AppContext) http.Handler {
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
			err := r.ParseMultipartForm(4096)
			if err != nil {
				log.WithFields(log.Fields{
					"user": string(user.Uid),
					"err":  err,
				}).Error("Failed to parse multipart form")
				ctx.RenderError(w, http.StatusInternalServerError)
				return
			}

			pubKey := ""

			files := r.MultipartForm.File["key_file"]
			if len(files) > 0 {
				// Only use first file
				file, err := files[0].Open()
				defer file.Close()
				if err != nil {
					log.WithFields(log.Fields{
						"user": string(user.Uid),
						"err":  err,
					}).Error("Failed to open ssh pub key file upload")
					ctx.RenderError(w, http.StatusInternalServerError)
					return
				}
				data, err := ioutil.ReadAll(file)
				if err != nil {
					log.WithFields(log.Fields{
						"user": string(user.Uid),
						"err":  err,
					}).Error("Failed to read ssh pub key file upload")
					ctx.RenderError(w, http.StatusInternalServerError)
					return
				}
				pubKey = string(data)
			} else {
				pubKey = r.FormValue("key")
			}

			sid := session.Values[app.CookieKeySID]
			err = addSSHPubKey(user, pubKey, sid.(string))

			if err == nil {
				session.Values[app.CookieKeyUser] = user
				session.AddFlash("SSH Public Key Added")
				session.Save(r, w)
				http.Redirect(w, r, "/sshpubkey", 302)
				return
			}

			message = err.Error()
		}

		vars := map[string]interface{}{
			"token":   nosurf.Token(r),
			"message": message,
			"user":    user}

		ctx.RenderTemplate(w, "new-ssh-pubkey.html", vars)
	})
}
