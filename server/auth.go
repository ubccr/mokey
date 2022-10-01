package server

import (
	"errors"
	"fmt"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
)

func isBlocked(username string) bool {
	blockUsers := viper.GetStringSlice("block_users")
	for _, u := range blockUsers {
		if username == u {
			return true
		}
	}

	return false
}

func (r *Router) isLoggedIn(c *fiber.Ctx) (bool, error) {
	sess, err := r.session(c)
	if err != nil {
		return false, errors.New("Failed to get session")
	}

	user := sess.Get(SessionKeyUser)
	sid := sess.Get(SessionKeySID)
	authenticated := sess.Get(SessionKeyAuthenticated)
	if sid == nil || user == nil || authenticated == nil {
		return false, errors.New("Invalid session")
	}

	if _, ok := user.(string); !ok {
		return false, errors.New("Invalid user in session")
	}

	if _, ok := sid.(string); !ok {
		return false, errors.New("Invalid sid in session")
	}

	if isAuthed, ok := authenticated.(bool); !ok || !isAuthed {
		return false, errors.New("User is not authenticated in session")
	}

	client := ipa.NewDefaultClientWithSession(sid.(string))
	_, err = client.Ping()
	if err != nil {
		return false, fmt.Errorf("Failed to refresh FreeIPA user session: %w", err)
	}

	c.Locals(ContextKeyUser, user)
	c.Locals(ContextKeyIPAClient, client)

	return true, nil
}

func (r *Router) Login(c *fiber.Ctx) error {
	vars := fiber.Map{}
	return c.Render("login.html", vars)
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
		}).Error("Logout failed to destroy session")
	}

	if viper.IsSet("hydra.admin_url") {
		if _, ok := username.(string); ok {
			err := r.revokeHydraAuthenticationSession(username.(string), c)
			if err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("Logout failed to revoke hydra authentication session")
			}
		}
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

func (r *Router) RequireNoLogin(c *fiber.Ctx) error {
	if ok, _ := r.isLoggedIn(c); ok {
		if c.Get("HX-Request", "false") == "true" {
			c.Set("HX-Redirect", "/")
			return c.Status(fiber.StatusNoContent).SendString("")
		}

		return c.Redirect("/")
	}

	return c.Next()
}

func (r *Router) RequireLogin(c *fiber.Ctx) error {
	if ok, err := r.isLoggedIn(c); !ok {
		log.WithFields(log.Fields{
			"path":  c.Path(),
			"ip":    c.IP(),
			"error": err,
		}).Info("Login required and no authenticated session found.")
		return r.redirectLogin(c)
	}

	return c.Next()
}

func (r *Router) CheckUser(c *fiber.Ctx) error {
	username := c.FormValue("username")

	if username == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Please provide a username")
	}

	if isBlocked(username) {
		log.WithFields(log.Fields{
			"username": username,
		}).Warn("User account is blocked from logging in")
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid credentials")
	}

	userRec, err := r.adminClient.UserShow(username)
	if err != nil {
		if ierr, ok := err.(*ipa.IpaError); ok && ierr.Code == 4001 {
			log.WithFields(log.Fields{
				"error":            err,
				"username":         username,
				"ipa_client_error": err,
			}).Warn("Username not found in FreeIPA")
			return c.Status(fiber.StatusUnauthorized).SendString("Invalid credentials")
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
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid credentials")
	}

	log.WithFields(log.Fields{
		"username": username,
		"ip":       c.IP(),
	}).Info("Login user attempt")

	vars := fiber.Map{
		"user":      userRec,
		"challenge": c.FormValue("challenge"),
	}

	return c.Render("login-form.html", vars)
}

func (r *Router) Authenticate(c *fiber.Ctx) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	challenge := c.FormValue("challenge")
	otp := c.FormValue("otp")

	if username == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Please provide a username")
	}

	if password == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Please provide a password")
	}

	if isBlocked(username) {
		log.WithFields(log.Fields{
			"username": username,
		}).Warn("User account is blocked from logging in")
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid credentials")
	}

	client := ipa.NewDefaultClient()
	err := client.RemoteLogin(username, password+otp)
	if err != nil {
		switch {
		case errors.Is(err, ipa.ErrExpiredPassword):
			log.WithFields(log.Fields{
				"username":         username,
				"ipa_client_error": err,
			}).Info("Password expired, forcing change")

			sess, err := r.session(c)
			if err != nil {
				return err
			}
			sess.Set(SessionKeyAuthenticated, false)
			sess.Set(SessionKeyUser, username)

			if err := r.sessionSave(c, sess); err != nil {
				return err
			}

			vars := fiber.Map{
				"username": username,
			}
			return c.Render("login-password-expired.html", vars)
		default:
			log.WithFields(log.Fields{
				"username":         username,
				"ipa_client_error": err,
			}).Error("Failed login attempt")
			return c.Status(fiber.StatusUnauthorized).SendString("Invalid credentials")
		}
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

	if viper.IsSet("hydra.admin_url") && challenge != "" {
		return r.LoginOAuthPost(username, challenge, c)
	}

	c.Set("HX-Redirect", "/")
	return c.Status(fiber.StatusNoContent).SendString("")
}
