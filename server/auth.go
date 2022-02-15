package server

import (
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/ubccr/goipa"
)

func (r *Router) Login(c *fiber.Ctx) error {
	return c.Render("login.html", fiber.Map{})
}

func (r *Router) Logout(c *fiber.Ctx) error {
	r.logout(c)
	return c.Redirect("/auth/login")
}

func (r *Router) logout(c *fiber.Ctx) {
	sess, err := r.session(c)
	if err != nil {
		return
	}

	uid := sess.Get(SessionKeyUser)
	if uid != nil {
		log.WithFields(log.Fields{
			"uid":  uid,
			"ip":   c.IP(),
			"path": c.Path(),
		}).Info("User logging out")
	}

	if err := sess.Destroy(); err != nil {
		log.WithFields(log.Fields{
			"uid":  uid,
			"ip":   c.IP(),
			"path": c.Path(),
			"err":  err,
		}).Error("Failed to destroy session")
	}
}

func (r *Router) LoginRequired(c *fiber.Ctx) error {
	sess, err := r.session(c)
	if err != nil {
		log.Warn("Failed to get user session. Logging out")
		r.logout(c)
		return c.Redirect("/auth/login")
	}

	user := sess.Get(SessionKeyUser)
	sid := sess.Get(SessionKeySID)
	if sid == nil || user == nil {
		return c.Redirect("/auth/login")
	}

	if _, ok := user.(string); !ok {
		log.Error("Invalid user in session")
		r.logout(c)
		return c.Redirect("/auth/login")
	}

	if _, ok := sid.(string); !ok {
		log.Error("Invalid sid in session")
		r.logout(c)
		return c.Redirect("/auth/login")
	}

	client := ipa.NewDefaultClientWithSession(sid.(string))
	_, err = client.Ping()
	if err != nil {
		log.WithFields(log.Fields{
			"uid":              user,
			"path":             c.Path(),
			"ip":               c.IP(),
			"ipa_client_error": err,
		}).Error("Failed to ping FreeIPA")
		r.logout(c)
		return c.Redirect("/auth/login")
	}

	c.Locals(ContextKeyUser, user)
	c.Locals(ContextKeyIPAClient, client)

	return c.Next()
}

func (r *Router) CheckUser(c *fiber.Ctx) error {
	c.Locals("partial", "true")
	uid := c.FormValue("uid")

	if uid == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Please provide a username")
	}

	userRec, err := r.client.UserShow(uid)
	if err != nil {
		if ierr, ok := err.(*ipa.IpaError); ok && ierr.Code == 4001 {
			log.WithFields(log.Fields{
				"error":            err,
				"uid":              uid,
				"ipa_client_error": err,
			}).Warn("Username not found in FreeIPA")
			return c.Status(fiber.StatusUnauthorized).SendString("Username not found")
		}

		log.WithFields(log.Fields{
			"error":            err,
			"uid":              uid,
			"ipa_client_error": err,
		}).Error("Failed to fetch user info from FreeIPA")
		return c.Status(fiber.StatusInternalServerError).SendString("Fatal system error")
	}

	if userRec.Locked() {
		log.WithFields(log.Fields{
			"uid": uid,
		}).Warn("User account is locked in FreeIPA")
		return c.Status(fiber.StatusUnauthorized).SendString("Username not found")

	}

	log.WithFields(log.Fields{
		"uid": uid,
		"ip":  c.IP(),
	}).Info("Login user attempt")

	vars := fiber.Map{
		"user": userRec,
	}

	return c.Render("login-form.html", vars)
}

func (r *Router) Authenticate(c *fiber.Ctx) error {
	c.Locals("partial", "true")
	uid := c.FormValue("uid")
	password := c.FormValue("password")
	otp := c.FormValue("otp")

	if uid == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Please provide a username")
	}

	if password == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Please provide a password")
	}

	client := ipa.NewDefaultClient()
	err := client.RemoteLogin(uid, password+otp)
	if err != nil {
		log.WithFields(log.Fields{
			"uid":              uid,
			"ipa_client_error": err,
		}).Error("Failed login attempt")
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid credentials")
	}

	_, err = client.Ping()
	if err != nil {
		log.WithFields(log.Fields{
			"uid":              uid,
			"ipa_client_error": err,
		}).Error("Failed to ping FreeIPA")
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid credentials")
	}

	sess, err := r.session(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("")
	}
	sess.Set(SessionKeyAuthenticated, true)
	sess.Set(SessionKeyUser, uid)
	sess.Set(SessionKeySID, client.SessionID())

	if err := r.sessionSave(c, sess); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("")
	}

	c.Set("HX-Redirect", "/")
	return c.Status(fiber.StatusNoContent).SendString("")
}
