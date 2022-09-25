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

	username := sess.Get(SessionKeyUser)
	if username != nil {
		log.WithFields(log.Fields{
			"username": username,
			"ip":       c.IP(),
			"path":     c.Path(),
		}).Info("User logging out")
	}

	if err := sess.Destroy(); err != nil {
		log.WithFields(log.Fields{
			"username": username,
			"ip":       c.IP(),
			"path":     c.Path(),
			"err":      err,
		}).Error("Failed to destroy session")
	}
}

func (r *Router) redirectLogin(c *fiber.Ctx) error {
	r.logout(c)

	if c.Get("HX-Request", "false") == "true" {
		c.Set("HX-Redirect", "/auth/login")
		return c.Status(fiber.StatusNoContent).SendString("")
	}

	return c.Redirect("/auth/login")
}

func (r *Router) RequireLogin(c *fiber.Ctx) error {
	sess, err := r.session(c)
	if err != nil {
		log.Warn("Failed to get user session. Logging out")
		return r.redirectLogin(c)
	}

	user := sess.Get(SessionKeyUser)
	sid := sess.Get(SessionKeySID)
	if sid == nil || user == nil {
		return r.redirectLogin(c)
	}

	if _, ok := user.(string); !ok {
		log.Error("Invalid user in session")
		return r.redirectLogin(c)
	}

	if _, ok := sid.(string); !ok {
		log.Error("Invalid sid in session")
		return r.redirectLogin(c)
	}

	client := ipa.NewDefaultClientWithSession(sid.(string))
	_, err = client.Ping()
	if err != nil {
		log.WithFields(log.Fields{
			"username":         user,
			"path":             c.Path(),
			"ip":               c.IP(),
			"ipa_client_error": err,
		}).Error("Failed to ping FreeIPA")
		return r.redirectLogin(c)
	}

	c.Locals(ContextKeyUser, user)
	c.Locals(ContextKeyIPAClient, client)

	return c.Next()
}

func (r *Router) CheckUser(c *fiber.Ctx) error {
	c.Locals("NoErrorTemplate", "true")
	username := c.FormValue("username")

	if username == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Please provide a username")
	}

	userRec, err := r.adminClient.UserShow(username)
	if err != nil {
		if ierr, ok := err.(*ipa.IpaError); ok && ierr.Code == 4001 {
			log.WithFields(log.Fields{
				"error":            err,
				"username":         username,
				"ipa_client_error": err,
			}).Warn("Username not found in FreeIPA")
			return c.Status(fiber.StatusUnauthorized).SendString("Username not found")
		}

		log.WithFields(log.Fields{
			"error":            err,
			"username":         username,
			"ipa_client_error": err,
		}).Error("Failed to fetch user info from FreeIPA")
		return c.Status(fiber.StatusInternalServerError).SendString("Fatal system error")
	}

	if userRec.Locked {
		log.WithFields(log.Fields{
			"username": username,
		}).Warn("User account is locked in FreeIPA")
		return c.Status(fiber.StatusUnauthorized).SendString("Username not found")

	}

	log.WithFields(log.Fields{
		"username": username,
		"ip":       c.IP(),
	}).Info("Login user attempt")

	vars := fiber.Map{
		"user": userRec,
	}

	return c.Render("login-form.html", vars)
}

func (r *Router) Authenticate(c *fiber.Ctx) error {
	c.Locals("NoErrorTemplate", "true")
	username := c.FormValue("username")
	password := c.FormValue("password")
	otp := c.FormValue("otp")

	if username == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Please provide a username")
	}

	if password == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Please provide a password")
	}

	client := ipa.NewDefaultClient()
	err := client.RemoteLogin(username, password+otp)
	if err != nil {
		log.WithFields(log.Fields{
			"username":         username,
			"ipa_client_error": err,
		}).Error("Failed login attempt")
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid credentials")
	}

	_, err = client.Ping()
	if err != nil {
		log.WithFields(log.Fields{
			"username":         username,
			"ipa_client_error": err,
		}).Error("Failed to ping FreeIPA")
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid credentials")
	}

	sess, err := r.session(c)
	if err != nil {
		return err
	}
	sess.Set(SessionKeyAuthenticated, true)
	sess.Set(SessionKeyUser, username)
	sess.Set(SessionKeySID, client.SessionID())

	if err := r.sessionSave(c, sess); err != nil {
		return err
	}

	c.Set("HX-Redirect", "/")
	return c.Status(fiber.StatusNoContent).SendString("")
}
