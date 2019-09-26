package server

import (
	"context"
	"net/http"
	"net/url"

	"github.com/labstack/echo"
	hydra "github.com/ory/hydra/sdk/go/hydra/client"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/model"
	"github.com/ubccr/mokey/util"
	"golang.org/x/oauth2"
	oidc "gopkg.in/coreos/go-oidc.v2"
)

type Handler struct {
	db      model.Datastore
	client  *ipa.Client
	emailer *util.Emailer

	// Hydra consent app support
	hydraClient *hydra.OryHydra
	apiClients  map[string]*model.ApiKeyClient

	// Globus signup support
	authUrl  *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func NewHandler(db model.Datastore) (*Handler, error) {
	h := &Handler{db: db}

	h.client = ipa.NewDefaultClient()

	err := h.client.LoginWithKeytab(viper.GetString("keytab"), viper.GetString("ktuser"))
	if err != nil {
		return nil, err
	}

	h.emailer, err = util.NewEmailer(db)
	if err != nil {
		return nil, err
	}

	h.client.StickySession(false)

	if viper.IsSet("hydra_admin_url") {
		adminURL, err := url.Parse(viper.GetString("hydra_admin_url"))
		if err != nil {
			log.Fatal(err)
		}
		h.hydraClient = hydra.NewHTTPClientWithConfig(
			nil,
			&hydra.TransportConfig{
				Schemes:  []string{adminURL.Scheme},
				Host:     adminURL.Host,
				BasePath: adminURL.Path,
			})
		log.Infof("Hydra consent/login endpoints enabled")

		if viper.IsSet("enabled_api_client_ids") {
			h.apiClients = make(map[string]*model.ApiKeyClient)

			ids := viper.GetStringSlice("enabled_api_client_ids")
			for _, clientID := range ids {
				if !viper.IsSet(clientID) {
					log.Fatalf("Api Client ID config not found: %s", clientID)
				}

				apiKeyConfig := viper.Sub(clientID)
				var a model.ApiKeyClient
				err = apiKeyConfig.Unmarshal(&a)
				if err != nil {
					log.Fatal(err)
				}

				log.Infof("Enabling oauth2 Api client: %s", clientID)
				a.ClientID = clientID
				h.apiClients[clientID] = &a
			}
		}
	}

	if viper.GetBool("globus_signup") {
		provider, err := oidc.NewProvider(context.Background(), viper.GetString("globus_iss"))
		if err != nil {
			log.Fatal(err)
		}

		clientID := viper.GetString("globus_client_id")
		h.authUrl = &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: viper.GetString("globus_secret"),
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{"openid", "profile", "urn:globus:auth:scope:auth.globus.org:view_identity_set", "email", "urn:globus:auth:scope:auth.globus.org:view_identities"},
			RedirectURL:  viper.GetString("email_link_base") + Path("/auth/globus/redirect"),
		}

		h.verifier = provider.Verifier(&oidc.Config{ClientID: clientID, SupportedSigningAlgs: []string{"RS512"}})
	}

	return h, nil
}

func (h *Handler) SetupRoutes(e *echo.Echo) {
	// Public
	e.GET(Path("/auth/captcha/*.png"), h.Captcha).Name = "captcha"

	// Login
	e.GET(Path("/auth/login"), h.LoginGet).Name = "login"
	e.POST(Path("/auth/login"), RateLimit(h.LoginPost))

	// Logout
	e.GET(Path("/auth/logout"), h.Logout).Name = "logout"

	if viper.GetBool("enable_user_signup") {
		// Signup
		e.GET(Path("/auth/signup"), h.Signup).Name = "signup"
		e.POST(Path("/auth/signup"), RateLimit(h.CreateAccount))
		e.Match([]string{"GET", "POST"}, Path("/auth/verify/*"), h.SetupAccount)[0].Name = "verify"
	}

	// Forgot Password
	e.Match([]string{"GET", "POST"}, Path("/auth/forgotpw"), RateLimit(h.ForgotPassword))[0].Name = "forgotpw"
	e.Match([]string{"GET", "POST"}, Path("/auth/resetpw/*"), RateLimit(h.ResetPassword))[0].Name = "resetpw"

	// Login Required
	e.GET(Path("/"), LoginRequired(h.Index)).Name = "index"
	e.Match([]string{"GET", "POST"}, Path("/changepw"), LoginRequired(h.ChangePassword))[0].Name = "changepw"
	e.GET(Path("/sshpubkey/new"), LoginRequired(h.NewSSHPubKey)).Name = "sshpubkey-new"
	e.POST(Path("/sshpubkey/new"), LoginRequired(h.AddSSHPubKey))
	e.Match([]string{"GET", "POST"}, Path("/sshpubkey"), LoginRequired(h.SSHPubKey))[0].Name = "sshpubkey"
	e.GET(Path("/otptokens"), LoginRequired(h.OTPTokens)).Name = "otptokens"
	e.POST(Path("/otptokens"), LoginRequired(h.ModifyOTPTokens))
	e.Match([]string{"GET", "POST"}, Path("/2fa"), LoginRequired(h.TwoFactorAuth))[0].Name = "2fa"

	if viper.IsSet("hydra_admin_url") {
		e.GET(Path("/oauth/consent"), h.ConsentGet).Name = "consent"
		e.POST(Path("/oauth/consent"), RateLimit(h.ConsentPost))
		e.GET(Path("/oauth/login"), h.LoginOAuthGet).Name = "login-oauth"
		e.POST(Path("/oauth/login"), RateLimit(h.LoginOAuthPost))
		e.GET(Path("/oauth/error"), h.HydraError).Name = "hydra-error"

		if viper.GetBool("enable_api_keys") {
			e.Match([]string{"GET", "POST"}, Path("/apikey"), LoginRequired(h.ApiKey))[0].Name = "apikey"
		}
	}

	if viper.GetBool("enable_user_signup") && viper.GetBool("globus_signup") {
		e.GET(Path("/auth/globus/redirect"), h.GlobusRedirect)
		e.GET(Path("/auth/globus"), h.GlobusSignup).Name = "globus"
	}
}

func (h *Handler) Index(c echo.Context) error {
	user := c.Get(ContextKeyUser)
	if user == nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user")
	}

	vars := map[string]interface{}{
		"user": user.(*ipa.UserRecord)}

	return c.Render(http.StatusOK, "index.html", vars)
}

func (h *Handler) removeAllOTPTokens(uid string) error {
	tokens, err := h.client.FetchOTPTokens(uid)
	if err != nil {
		return err
	}

	for _, t := range tokens {
		err = h.client.RemoveOTPToken(string(t.UUID))
		if err != nil {
			return err
		}
	}

	return nil
}
