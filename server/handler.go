package server

import (
	"context"
	"net/http"

	"github.com/labstack/echo"
	"github.com/ory/hydra/sdk"
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
	hydraClient *sdk.Client
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

	if viper.IsSet("hydra_cluster_url") {
		h.hydraClient, err = sdk.Connect(
			sdk.ClientID(viper.GetString("hydra_client_id")),
			sdk.ClientSecret(viper.GetString("hydra_client_secret")),
			sdk.SkipTLSVerify(viper.GetBool("develop")),
			sdk.Scopes("hydra.keys.get"),
			sdk.ClusterURL(viper.GetString("hydra_cluster_url")))

		if err != nil {
			log.Fatal(err)
		}

		log.Infof("Hydra consent app enabled")

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
			RedirectURL:  viper.GetString("email_link_base") + "/auth/globus/redirect",
		}

		h.verifier = provider.Verifier(&oidc.Config{ClientID: clientID, SupportedSigningAlgs: []string{"RS512"}})
	}

	return h, nil
}

func (h *Handler) SetupRoutes(e *echo.Echo) {
	// Public
	e.GET("/auth/captcha/*.png", h.Captcha).Name = "captcha"

	// Login
	e.GET("/auth/login", h.Signin).Name = "login"
	e.POST("/auth/login", RateLimit(h.Login))

	// Logout
	e.GET("/auth/logout", h.Logout).Name = "logout"

	// Signup
	e.GET("/auth/signup", h.Signup).Name = "signup"
	e.POST("/auth/signup", RateLimit(h.CreateAccount))
	e.Match([]string{"GET", "POST"}, "/auth/verify/*", h.SetupAccount)[0].Name = "verify"

	// Forgot Password
	e.Match([]string{"GET", "POST"}, "/auth/forgotpw", RateLimit(h.ForgotPassword))[0].Name = "forgotpw"
	e.Match([]string{"GET", "POST"}, "/auth/resetpw/*", RateLimit(h.ResetPassword))[0].Name = "resetpw"

	// Login Required
	e.GET("/", LoginRequired(h.Index)).Name = "index"
	e.Match([]string{"GET", "POST"}, "/changepw", LoginRequired(h.ChangePassword))[0].Name = "changepw"
	e.GET("/sshpubkey/new", LoginRequired(h.NewSSHPubKey)).Name = "sshpubkey-new"
	e.POST("/sshpubkey/new", LoginRequired(h.AddSSHPubKey))
	e.Match([]string{"GET", "POST"}, "/sshpubkey", LoginRequired(h.SSHPubKey))[0].Name = "sshpubkey"
	e.GET("/otptokens", LoginRequired(h.OTPTokens)).Name = "otptokens"
	e.POST("/otptokens", LoginRequired(h.ModifyOTPTokens))
	e.Match([]string{"GET", "POST"}, "/2fa", LoginRequired(h.TwoFactorAuth))[0].Name = "2fa"

	if viper.IsSet("hydra_cluster_url") {
		e.Match([]string{"GET", "POST"}, "/consent", RateLimit(LoginRequired(h.Consent)))[0].Name = "consent"

		if viper.GetBool("enable_api_keys") {
			e.Match([]string{"GET", "POST"}, "/apikey", LoginRequired(h.ApiKey))[0].Name = "apikey"
		}
	}

	if viper.GetBool("globus_signup") {
		e.GET("/auth/globus/redirect", h.GlobusRedirect)
		e.GET("/auth/globus", h.GlobusSignup).Name = "globus"
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
