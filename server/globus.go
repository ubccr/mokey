// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

type GlobusIdentities struct {
	Identities []*GlobusIdentity `json:"identities"`
	Included   struct {
		IdentityProviders []*GlobusIdentityProvider `json:"identity_providers"`
	} `json:"included"`
}

type GlobusIdentityProvider struct {
	Name      string   `json:"name"`
	ShortName string   `json:"short_name"`
	ID        string   `json:"id"`
	Domains   []string `json:"domains"`
}

type GlobusIdentity struct {
	Active           bool     `json:"active"`
	Aud              []string `json:"aud"`
	ClientID         string   `json:"client_id"`
	Email            string   `json:"email"`
	Exp              int      `json:"exp"`
	IAt              int      `json:"iat"`
	NBF              int      `json:"nbf"`
	IdentitiesSet    []string `json:"identities_set"`
	IdentityProvider string   `json:"identity_provider"`
	ISS              string   `json:"iss"`
	Name             string   `json:"name"`
	Scope            string   `json:"scope"`
	Sub              string   `json:"sub"`
	Status           string   `json:"status"`
	TokenType        string   `json:"token_type"`
	Username         string   `json:"username"`
	Organization     string   `json:"organization"`
	ID               string   `json:"id"`
}

type GlobusIDTokenClaims struct {
	Aud                         string `json:"aud"`
	IdentityProviderDisplayName string `json:"identity_provider_display_name"`
	Sub                         string `json:"sub"`
	ISS                         string `json:"iss"`
	PreferredUsername           string `json:"preferred_username"`
	AtHash                      string `json:"at_hash"`
	IdentityProvider            string `json:"identity_provider"`
	Exp                         int    `json:"exp"`
	IAt                         int    `json:"iat"`
	Organization                string `json:"organization"`
	Email                       string `json:"email"`
	Name                        string `json:"name"`
}

func (g *GlobusIdentity) CleanUsername() string {
	parts := strings.Split(g.Username, "@")
	return parts[0]
}

func (h *Handler) GlobusSignup(c echo.Context) error {
	sess, err := session.Get(CookieKeySession, c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get session")
	}

	state, err := h.db.RandToken()
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Error("failed to generate state")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to generate state")
	}

	vars := map[string]interface{}{
		"flashes":   sess.Flashes(),
		"globusURL": h.authUrl.AuthCodeURL(state),
	}

	sess.Values[CookieKeyState] = state
	sess.Save(c.Request(), c.Response())

	return c.Render(http.StatusOK, "globus-signup.html", vars)
}

func (h *Handler) GlobusRedirect(c echo.Context) error {
	log.WithFields(log.Fields{
		"url": c.Request().URL.String(),
	}).Info("got globus redirect")

	sess, err := session.Get(CookieKeySession, c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get session")
	}

	username, err := h.fetchGlobusUsername(c)
	if err != nil {
		sess.AddFlash(err.Error())
		sess.Save(c.Request(), c.Response())
		return c.Redirect(http.StatusFound, "/auth/globus")
	}

	sess.Values[CookieKeyGlobus] = true
	sess.Values[CookieKeyGlobusUsername] = username
	sess.Save(c.Request(), c.Response())

	return c.Redirect(http.StatusFound, "/auth/signup")
}

func (h *Handler) fetchGlobusUsername(c echo.Context) (string, error) {
	sess, _ := session.Get(CookieKeySession, c)

	state := sess.Values[CookieKeyState]
	if state == nil {
		return "", errors.New("Invalid request")
	}
	if _, ok := state.(string); !ok {
		return "", errors.New("Invalid request")
	}

	if state != c.QueryParam("state") {
		log.WithFields(log.Fields{
			"expected": state,
			"got":      c.QueryParam("state"),
		}).Error("invalid state")
		return "", errors.New("Invalid request")
	}

	gid, err := h.fetchGlobusIdentity(c.QueryParam("code"))
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Failed to fetch globus identity")
		return "", errors.New("We were unable to verify your identity. It could be that you do not have an identity with one of our trusted organizations or there was an error communicating with Globus. Please contact an administrator.")
	}

	username := gid.CleanUsername()

	if len(username) == 0 {
		log.WithFields(log.Fields{
			"globus_username": gid.Username,
		}).Error("Failed to parse globus username")
		return "", errors.New("Invalid username returned from identity provider. Please contact an administrator.")
	}

	if viper.GetBool("develop") {
		username += "1234"
	}

	_, err = h.client.UserShow(username)
	if err == nil {
		log.WithFields(log.Fields{
			"username": username,
		}).Warn("User already exists")
		return "", errors.New("A user with this account already exists in our system. If you feel this is an error please contact an administrator.")
	}

	return username, nil
}

func (h *Handler) fetchGlobusIdentity(code string) (*GlobusIdentity, error) {
	ctx := context.Background()
	token, err := h.authUrl.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("Failed to get id_token")
	}

	idToken, err := h.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}

	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *GlobusIDTokenClaims
	}{token, new(GlobusIDTokenClaims)}

	if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
		return nil, err
	}

	v := url.Values{}
	v.Set("token", token.AccessToken)
	v.Set("include", "identities_set")

	req, err := http.NewRequest("POST", viper.GetString("globus_iss")+"/v2/oauth2/token/introspect", strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(h.authUrl.ClientID, h.authUrl.ClientSecret)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("Failed to fetch identity set with HTTP status code: %d", res.StatusCode)
	}

	rawJson, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	defaultIdentity := &GlobusIdentity{}
	err = json.Unmarshal(rawJson, defaultIdentity)
	if err != nil {
		return nil, err
	}

	if !defaultIdentity.Active {
		return nil, errors.New("Globus identity not active")
	}

	if viper.IsSet("globus_trusted_providers") {
		// Need to check that user has an identity from a trusted provider
		tid, err := h.fetchTrustedIdentity(defaultIdentity.IdentitiesSet, viper.GetStringSlice("globus_trusted_providers"))
		if err != nil {
			return nil, err
		}

		defaultIdentity = tid
	}

	return defaultIdentity, nil
}

func (h *Handler) fetchTrustedIdentity(ids, trustedProviders []string) (*GlobusIdentity, error) {
	idList := strings.Join(ids, ",")
	req, err := http.NewRequest("GET", viper.GetString("globus_iss")+"/v2/api/identities?include=identity_provider&ids="+idList, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(h.authUrl.ClientID, h.authUrl.ClientSecret)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("Failed to fetch identity set with HTTP status code: %d", res.StatusCode)
	}

	rawJson, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var gids GlobusIdentities
	err = json.Unmarshal(rawJson, &gids)
	if err != nil {
		return nil, err
	}

	providerID := ""
	for _, provider := range gids.Included.IdentityProviders {
		for _, trusted := range trustedProviders {
			if provider.Name == trusted {
				log.WithFields(log.Fields{
					"name":    provider.Name,
					"short":   provider.ShortName,
					"id":      provider.ID,
					"domains": provider.Domains,
				}).Info("Found trusted provider")

				providerID = provider.ID
				break
			}
		}
	}

	if len(providerID) == 0 {
		return nil, errors.New("No identity found with trusted provider")
	}

	for _, id := range gids.Identities {
		if id.IdentityProvider == providerID && id.Status == "used" {
			return id, nil
		}
	}

	return nil, fmt.Errorf("No identity found with trusted provider: %s", providerID)
}
