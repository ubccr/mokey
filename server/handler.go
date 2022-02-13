package server

import (
	"context"
	"net/http"
	"net/url"

	oidc "github.com/coreos/go-oidc"
	"github.com/labstack/echo/v4"
	hydra "github.com/ory/hydra-client-go/client"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/util"
	"golang.org/x/oauth2"
)

type Handler struct {
	client  *ipa.Client
	emailer *util.Emailer

	// Hydra consent app support
	hydraClient          *hydra.OryHydra
	hydraAdminHTTPClient *http.Client

	// Globus signup support
	authUrl  *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

type FakeTLSTransport struct {
	T http.RoundTripper
}

func (ftt *FakeTLSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("X-Forwarded-Proto", "https")
	return ftt.T.RoundTrip(req)
}

func NewHandler() (*Handler, error) {
	h := &Handler{}

	h.client = ipa.NewDefaultClient()

	err := h.client.LoginWithKeytab(viper.GetString("keytab"), viper.GetString("ktuser"))
	if err != nil {
		return nil, err
	}

	h.emailer, err = util.NewEmailer()
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

		if viper.GetBool("hydra_fake_tls_termination") {
			h.hydraAdminHTTPClient = &http.Client{
				Transport: &FakeTLSTransport{T: http.DefaultTransport},
			}
		} else {
			h.hydraAdminHTTPClient = http.DefaultClient
		}

		log.Infof("Hydra consent/login endpoints enabled")
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
	e.GET("/", h.Index).Name = "index"
	e.GET("/auth/login", h.LoginGet).Name = "login"
	e.POST("/auth/login", h.LoginPost).Name = "login-post"
	e.GET("/security", h.Security).Name = "security"
	e.GET("/sshkeys", h.SSHKeys).Name = "sshkeys"
	e.GET("/otp", h.OTPTokens).Name = "otptokens"
	e.GET("/password", h.Password).Name = "password"
}

func (h *Handler) Index(c echo.Context) error {
	vars := map[string]interface{}{
		"user": "test",
		"page": "account",
	}

	return c.Render(http.StatusOK, "index.html", vars)
}

func (h *Handler) SSHKeys(c echo.Context) error {
	vars := map[string]interface{}{
		"user": "test",
		"page": "sshkeys",
	}

	return c.Render(http.StatusOK, "ssh-keys.html", vars)
}

func (h *Handler) Security(c echo.Context) error {
	vars := map[string]interface{}{
		"user": "test",
		"page": "security",
	}

	return c.Render(http.StatusOK, "security.html", vars)
}

func (h *Handler) Password(c echo.Context) error {
	vars := map[string]interface{}{
		"user": "test",
		"page": "password",
	}

	return c.Render(http.StatusOK, "password.html", vars)
}

func (h *Handler) OTPTokens(c echo.Context) error {
	vars := map[string]interface{}{
		"user": "test",
		"page": "otp",
	}

	return c.Render(http.StatusOK, "otp-tokens.html", vars)
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
