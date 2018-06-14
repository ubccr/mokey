package server

import (
	"net/http"

	"github.com/labstack/echo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/model"
	"github.com/ubccr/mokey/util"
)

type Handler struct {
	db         model.Datastore
	client     *ipa.Client
	emailer    *util.Emailer
	apiClients map[string]*model.ApiKeyClient
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

	return h, nil
}

func (h *Handler) SetupRoutes(e *echo.Echo) {
	// Public
	e.GET("/auth/captcha/*.png", h.Captcha)

	// Login
	e.GET("/auth/login", h.Signin)
	e.POST("/auth/login", h.Login)

	// Logout
	e.GET("/auth/logout", h.Logout)

	// Signup
	e.GET("/auth/signup", h.Signup)
	e.POST("/auth/signup", h.CreateAccount)
	e.Match([]string{"GET", "POST"}, "/auth/verify/*", h.SetupAccount)

	// Forgot Password
	e.Match([]string{"GET", "POST"}, "/auth/forgotpw", h.ForgotPassword)
	e.Match([]string{"GET", "POST"}, "/auth/resetpw/*", h.ResetPassword)

	// Login Required
	e.GET("/", LoginRequired(h.Index))
	e.Match([]string{"GET", "POST"}, "/changepw", LoginRequired(h.ChangePassword))
	e.GET("/sshpubkey/new", LoginRequired(h.NewSSHPubKey))
	e.POST("/sshpubkey/new", LoginRequired(h.AddSSHPubKey))
	e.Match([]string{"GET", "POST"}, "/sshpubkey", LoginRequired(h.SSHPubKey))
	e.GET("/otptokens", LoginRequired(h.OTPTokens))
	e.POST("/otptokens", LoginRequired(h.ModifyOTPTokens))
	e.Match([]string{"GET", "POST"}, "/2fa", LoginRequired(h.TwoFactorAuth))

	if viper.GetBool("enable_api_keys") {
		e.Match([]string{"GET", "POST"}, "/apikey", LoginRequired(h.ApiKey))
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
