package server

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/util"
)

type Router struct {
	adminClient  *ipa.Client
	sessionStore *session.Store
	emailer      *util.Emailer
	storage      fiber.Storage
}

func NewRouter(storage fiber.Storage) (*Router, error) {
	r := &Router{
		storage: storage,
	}

	r.adminClient = ipa.NewDefaultClient()

	err := r.adminClient.LoginWithKeytab(viper.GetString("keytab"), viper.GetString("ktuser"))
	if err != nil {
		return nil, err
	}

	r.adminClient.StickySession(false)

	r.sessionStore = session.New(session.Config{
		Storage:        storage,
		CookieSecure:   !viper.GetBool("develop"),
		CookieHTTPOnly: true,
	})

	r.emailer, err = util.NewEmailer()
	if err != nil {
		return nil, err
	}

	return r, nil
}

func (r *Router) session(c *fiber.Ctx) (*session.Session, error) {
	sess, err := r.sessionStore.Get(c)
	if err != nil {
		log.WithFields(log.Fields{
			"path": c.Path(),
			"err":  err,
			"ip":   c.IP(),
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
			"ip":   c.IP(),
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
	app.Get("/signup", r.AccountCreate)
	app.Post("/signup", r.AccountCreate)

	// Auth
	app.Get("/auth/login", r.Login)
	app.Get("/auth/logout", r.Logout)
	app.Post("/auth/login", r.CheckUser)
	app.Post("/auth/authenticate", r.Authenticate)
	app.Get("/auth/captcha/:id.png", r.Captcha)
	app.Get("/auth/verify/:token", r.AccountVerify)
	app.Post("/auth/verify/:token", r.AccountVerify)

	// Account Settings
	app.Get("/account/settings", r.RequireLogin, r.RequireHTMX, r.AccountSettings)
	app.Post("/account/settings", r.RequireLogin, r.RequireHTMX, r.AccountSettings)

	// Password
	app.Get("/password/change", r.RequireLogin, r.RequireHTMX, r.ChangePassword)
	app.Post("/password/change", r.RequireLogin, r.RequireHTMX, r.ChangePassword)

	// Security
	app.Get("/security/settings", r.RequireLogin, r.RequireHTMX, r.SecurityList)
	app.Post("/security/mfa/enable", r.RequireLogin, r.RequireHTMX, r.TwoFactorEnable)
	app.Post("/security/mfa/disable", r.RequireLogin, r.RequireHTMX, r.TwoFactorDisable)

	// SSH Keys
	app.Get("/sshkey/list", r.RequireLogin, r.RequireHTMX, r.SSHKeyList)
	app.Get("/sshkey/modal", r.RequireLogin, r.RequireHTMX, r.SSHKeyModal)
	app.Post("/sshkey/add", r.RequireLogin, r.RequireHTMX, r.SSHKeyAdd)
	app.Post("/sshkey/remove", r.RequireLogin, r.RequireHTMX, r.SSHKeyRemove)

	// OTP Tokens
	app.Get("/otptoken/list", r.RequireLogin, r.RequireHTMX, r.OTPTokenList)
	app.Get("/otptoken/modal", r.RequireLogin, r.RequireHTMX, r.OTPTokenModal)
	app.Post("/otptoken/add", r.RequireLogin, r.RequireHTMX, r.OTPTokenAdd)
	app.Post("/otptoken/verify", r.RequireLogin, r.RequireHTMX, r.OTPTokenVerify)
	app.Post("/otptoken/remove", r.RequireLogin, r.RequireHTMX, r.OTPTokenRemove)
	app.Post("/otptoken/enable", r.RequireLogin, r.RequireHTMX, r.OTPTokenEnable)
	app.Post("/otptoken/disable", r.RequireLogin, r.RequireHTMX, r.OTPTokenDisable)
}

func (r *Router) userClient(c *fiber.Ctx) *ipa.Client {
	return c.Locals(ContextKeyIPAClient).(*ipa.Client)
}

func (r *Router) username(c *fiber.Ctx) string {
	return c.Locals(ContextKeyUser).(string)
}

func (r *Router) user(c *fiber.Ctx) (*ipa.User, error) {
	username := c.Locals(ContextKeyUser).(string)
	client := c.Locals(ContextKeyIPAClient).(*ipa.Client)

	return client.UserShow(username)
}

func (r *Router) Index(c *fiber.Ctx) error {
	user, err := r.user(c)
	if err != nil {
		return err
	}

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
