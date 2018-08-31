package main

// This is an example OAuth 2.0 client app using OpenID Connect. It is not
// meant for use in a production environment and only for testing
// FreeIPA->mokey->hydra integration. Configuration is via environment
// variables (see mokey-oidc.conf)
//
// This code was adopted from https://github.com/ory/hydra-consent-app-go

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"

	oidc "github.com/coreos/go-oidc"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/urfave/negroni"
	"golang.org/x/oauth2"
)

// A state for performing the OAuth 2.0 flow
var state = "mokeydemostate"

var (
	cert         string
	key          string
	authUrl      *oauth2.Config
	homeTmpl     *template.Template
	callbackTmpl *template.Template
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", handleHome)
	r.HandleFunc("/callback", handleCallback)

	n := negroni.New()
	n.UseHandler(r)

	http.ListenAndServeTLS(fmt.Sprintf(":%s", os.Getenv("MOKEY_OIDC_PORT")), cert, key, n)
	fmt.Println(fmt.Sprintf("Listening on :%s", os.Getenv("MOKEY_OIDC_PORT")))
}

func handleHome(w http.ResponseWriter, _ *http.Request) {
	var u = authUrl.AuthCodeURL(state) + "&nonce=" + state
	err := homeTmpl.Execute(w, u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// After the user gave his consent, they will hit this endpoint. The mokey
// consent app includes some extra user info in the id_token.
func handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	})

	provider, err := oidc.NewProvider(ctx, os.Getenv("MOKEY_OIDC_PROVIDER"))
	if err != nil {
		http.Error(w, errors.Wrap(err, "Could not create provider").Error(), http.StatusBadRequest)
		return
	}

	oidcConfig := &oidc.Config{
		ClientID: authUrl.ClientID,
	}
	verifier := provider.Verifier(oidcConfig)

	token, err := authUrl.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, errors.Wrap(err, "Could not exhange token").Error(), http.StatusBadRequest)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, errors.Wrap(err, "No id_token field in oauth2 token").Error(), http.StatusBadRequest)
		return
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, errors.Wrap(err, "Failed to verify id token").Error(), http.StatusBadRequest)
		return
	}

	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *json.RawMessage
	}{token, new(json.RawMessage)}

	if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
		http.Error(w, errors.Wrap(err, "Failed to get claims").Error(), http.StatusBadRequest)
		return
	}
	data, err := json.MarshalIndent(resp, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = callbackTmpl.Execute(w, struct {
		*oauth2.Token
		UserInfo string
		IDToken  interface{}
	}{
		Token:    token,
		UserInfo: string(data),
		IDToken:  token.Extra("id_token"),
	})

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func init() {
	authUrl = &oauth2.Config{
		ClientID:     os.Getenv("MOKEY_OIDC_CLIENT_ID"),
		ClientSecret: os.Getenv("MOKEY_OIDC_CLIENT_SECRET"),
		Endpoint: oauth2.Endpoint{
			TokenURL: os.Getenv("MOKEY_OIDC_TOKEN_URL"),
			AuthURL:  os.Getenv("MOKEY_OIDC_AUTH_URL"),
		},
		Scopes:      []string{"openid"},
		RedirectURL: os.Getenv("MOKEY_OIDC_REDIRECT_URL"),
	}

	cert = os.Getenv("MOKEY_OIDC_CERT")
	key = os.Getenv("MOKEY_OIDC_KEY")

	homeTmpl = template.Must(template.New("home.html").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Welcome!</title>
</head>
<body>
    <p>
        Click <a href="{{.}}">here</a> to perform the exemplary authorize code flow.
    </p>
</body>
</html>`))

	callbackTmpl = template.Must(template.New("callback.html").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Success!</title>
</head>
<body>
    <p>
        OAuth2 authorize code flow was performed successfully!
    </p>
    <dl>
        <dt>AccessToken</dt>
        <dd><code>{{.AccessToken}}</code></dd>
        <dt>TokenType</dt>
        <dd><code>{{.TokenType}}</code></dd>
        <dt>RefreshToken</dt>
        <dd><code>{{.RefreshToken}}</code></dd>
        <dt>Expiry</dt>
        <dd><code>{{.Expiry}}</code></dd>
        <dt>ID Token</dt>
        <dd><code>{{.IDToken}}</code></dd>
        <dt>UserInfo</dt>
        <dd><code>{{.UserInfo}}</code></dd>
    </dl>
    <p>
        <a href="/">Do it again</a>
    </p>
</body>
</html>`))
}
