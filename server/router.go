package server

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	hydra "github.com/ory/hydra-client-go/client"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	ipa "github.com/ubccr/goipa"
)

type Router struct {
	adminClient  *ipa.Client
	sessionStore *session.Store
	emailer      *Emailer
	storage      fiber.Storage

	// Hydra consent app support
	hydraClient          *hydra.OryHydra
	hydraAdminHTTPClient *http.Client

	// Prometheus metrics
	metrics *Metrics
}

func NewRouter(storage fiber.Storage) (*Router, error) {
	r := &Router{
		storage: storage,
	}

	r.adminClient = ipa.NewDefaultClient()

	err := r.adminClient.LoginWithKeytab(viper.GetString("site.keytab"), viper.GetString("site.ktuser"))
	if err != nil {
		return nil, err
	}

	r.adminClient.StickySession(false)

	r.sessionStore = session.New(session.Config{
		Storage:        storage,
		CookieSameSite: "Strict",
		CookieSecure:   viper.GetBool("server.secure_cookies"),
		CookieHTTPOnly: true,
	})

	r.emailer, err = NewEmailer(storage)
	if err != nil {
		return nil, err
	}

	if viper.IsSet("hydra.admin_url") {
		adminURL, err := url.Parse(viper.GetString("hydra.admin_url"))
		if err != nil {
			log.Fatal(err)
		}

		r.hydraClient = hydra.NewHTTPClientWithConfig(
			nil,
			&hydra.TransportConfig{
				Schemes:  []string{adminURL.Scheme},
				Host:     adminURL.Host,
				BasePath: adminURL.Path,
			})

		if viper.GetBool("hydra.fake_tls_termination") {
			r.hydraAdminHTTPClient = &http.Client{
				Transport: &FakeTLSTransport{T: http.DefaultTransport},
			}
		} else {
			r.hydraAdminHTTPClient = http.DefaultClient
		}
	}

	r.metrics = NewMetrics()

	return r, nil
}

func RemoteIP(c *fiber.Ctx) string {
	ips := c.IPs()
	if len(ips) > 0 {
		return strings.Join(ips, ",")
	}

	return c.IP()
}

func (r *Router) session(c *fiber.Ctx) (*session.Session, error) {
	sess, err := r.sessionStore.Get(c)
	if err != nil {
		log.WithFields(log.Fields{
			"path": c.Path(),
			"err":  err,
			"ip":   RemoteIP(c),
		}).Error("Failed to fetch session from storage")

		return nil, err
	}

	return sess, nil
}

func (r *Router) sessionSave(c *fiber.Ctx, sess *session.Session) error {
	if err := sess.Save(); err != nil {
		log.WithFields(log.Fields{
			"path": c.Path(),
			"err":  err,
			"ip":   RemoteIP(c),
		}).Error("Failed to save session to storage")

		return err
	}

	return nil
}

func (r *Router) SetupRoutes(app *fiber.App) {
	app.Get("/", r.RequireLogin, r.Index)
	app.Get("/account", r.RequireLogin, r.Index)
	app.Get("/password", r.RequireLogin, r.Index)
	app.Get("/security", r.RequireLogin, r.Index)
	app.Get("/sshkey", r.RequireLogin, r.Index)
	app.Get("/otp", r.RequireLogin, r.Index)

	// Account Create
	app.Get("/signup", r.RequireNoLogin, r.AccountCreate)
	app.Post("/signup", r.RequireNoLogin, r.AccountCreate)

	// Auth
	app.Get("/auth/login", r.RequireNoLogin, r.Login)
	app.Post("/auth/login", r.RequireNoLogin, r.CheckUser)
	app.Post("/auth/authenticate", r.RequireNoLogin, r.Authenticate)
	app.Post("/auth/expiredpw", r.RequireNoLogin, r.PasswordExpired)
	app.Get("/auth/forgotpw", r.RequireNoLogin, r.PasswordForgot)
	app.Post("/auth/forgotpw", r.RequireNoLogin, r.PasswordForgot)
	app.Get("/auth/verify", r.RequireNoLogin, r.AccountVerifyResend)
	app.Post("/auth/verify", r.RequireNoLogin, r.AccountVerifyResend)
	app.Get("/auth/resetpw/:token", r.PasswordReset)
	app.Post("/auth/resetpw/:token", r.PasswordReset)
	app.Get("/auth/verify/:token", r.AccountVerify)
	app.Post("/auth/verify/:token", r.AccountVerify)
	app.Get("/auth/logout", r.Logout)
	app.Get("/auth/captcha/:id.png", r.Captcha)

	// Account Settings
	app.Get("/account/settings", r.RequireLogin, r.RequireHTMX, r.AccountSettings)
	app.Post("/account/settings", r.RequireLogin, r.RequireHTMX, r.AccountSettings)

	// Password
	app.Get("/password/change", r.RequireLogin, r.RequireHTMX, r.PasswordChange)
	app.Post("/password/change", r.RequireLogin, r.RequireHTMX, r.PasswordChange)

	// Security
	app.Get("/security/settings", r.RequireLogin, r.RequireHTMX, r.SecurityList)
	app.Post("/security/mfa/enable", r.RequireLogin, r.RequireHTMX, r.TwoFactorEnable)
	app.Post("/security/mfa/disable", r.RequireLogin, r.RequireHTMX, r.TwoFactorDisable)

	// SSH Keys
	app.Get("/sshkey/list", r.RequireLogin, r.RequireHTMX, r.SSHKeyList)
	app.Get("/sshkey/modal", r.RequireLogin, r.RequireHTMX, r.SSHKeyModal)
	app.Post("/sshkey/add", r.RequireLogin, r.RequireMFA, r.RequireHTMX, r.SSHKeyAdd)
	app.Post("/sshkey/remove", r.RequireLogin, r.RequireMFA, r.RequireHTMX, r.SSHKeyRemove)

	// OTP Tokens
	app.Get("/otptoken/list", r.RequireLogin, r.RequireHTMX, r.OTPTokenList)
	app.Get("/otptoken/modal", r.RequireLogin, r.RequireHTMX, r.OTPTokenModal)
	app.Post("/otptoken/add", r.RequireLogin, r.RequireHTMX, r.OTPTokenAdd)
	app.Post("/otptoken/verify", r.RequireLogin, r.RequireHTMX, r.OTPTokenVerify)
	app.Post("/otptoken/remove", r.RequireLogin, r.RequireHTMX, r.OTPTokenRemove)
	app.Post("/otptoken/enable", r.RequireLogin, r.RequireHTMX, r.OTPTokenEnable)
	app.Post("/otptoken/disable", r.RequireLogin, r.RequireHTMX, r.OTPTokenDisable)

	if viper.IsSet("site.logo") {
		app.Get("/images/logo", r.Logo)
	}

	if viper.IsSet("site.css") {
		app.Get("/css/styles", r.Styles)
	}

	if viper.IsSet("hydra.admin_url") {
		app.Get("/oauth/consent", r.ConsentGet)
		app.Get("/oauth/login", r.LoginOAuthGet)
		app.Get("/oauth/error", r.HydraError)
	}

	// Prometheus metrics
	if viper.GetBool("server.enable_metrics") {
		app.Get("/metrics", r.Metrics)
	}
}

func (r *Router) userClient(c *fiber.Ctx) *ipa.Client {
	return c.Locals(ContextKeyIPAClient).(*ipa.Client)
}

func (r *Router) username(c *fiber.Ctx) string {
	return c.Locals(ContextKeyUsername).(string)
}

func (r *Router) user(c *fiber.Ctx) *ipa.User {
	return c.Locals(ContextKeyUser).(*ipa.User)
}

func (r *Router) Index(c *fiber.Ctx) error {
	user := r.user(c)

	path := strings.TrimPrefix(c.Path(), "/")
	if path == "" {
		path = "account"
	}

	vars := fiber.Map{
		"user": user,
		"path": path,
	}

	if path == "sshkey" {
		vars["keys"] = user.SSHAuthKeys
	} else if path == "otp" {
		username := r.username(c)
		client := r.userClient(c)

		tokens, err := client.FetchOTPTokens(username)
		if err != nil {
			return err
		}

		vars["otptokens"] = tokens
	}

	return c.Render("index.html", vars)
}

func (r *Router) Logo(c *fiber.Ctx) error {
	if viper.IsSet("site.logo") {
		return c.SendFile(viper.GetString("site.logo"))
	}

	return c.Status(fiber.StatusNotFound).SendString("")
}

func (r *Router) Styles(c *fiber.Ctx) error {
	if viper.IsSet("site.css") {
		return c.SendFile(viper.GetString("site.css"))
	}

	return c.Status(fiber.StatusNotFound).SendString("")
}

func (r *Router) Metrics(c *fiber.Ctx) error {
	return r.metrics.Handler(c)
}
