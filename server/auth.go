package server

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	ipa "github.com/ubccr/goipa"
)

func isBlocked(username string) bool {
	blockUsers := viper.GetStringSlice("accounts.block_users")
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

	username := sess.Get(SessionKeyUsername)
	sid := sess.Get(SessionKeySID)
	authenticated := sess.Get(SessionKeyAuthenticated)
	if sid == nil || username == nil || authenticated == nil {
		return false, errors.New("Invalid session")
	}

	if _, ok := username.(string); !ok {
		return false, errors.New("Invalid user in session")
	}

	if _, ok := sid.(string); !ok {
		return false, errors.New("Invalid sid in session")
	}

	if isAuthed, ok := authenticated.(bool); !ok || !isAuthed {
		return false, errors.New("User is not authenticated in session")
	}

	client := ipa.NewDefaultClientWithSession(sid.(string))
	user, err := client.UserShow(username.(string))
	if err != nil {
		return false, fmt.Errorf("Failed to refresh FreeIPA user session: %w", err)
	}

	c.Locals(ContextKeyUsername, username)
	c.Locals(ContextKeyUser, user)
	c.Locals(ContextKeyIPAClient, client)

	// Update session expiry time
	sess.SetExpiry(time.Duration(viper.GetInt("server.session_idle_timeout")) * time.Second)

	sess.Save()

	return true, nil
}

func (r *Router) Login(c *fiber.Ctx) error {
	r.logAuthStep(c, "login_get", nil)

	vars := fiber.Map{}
	if challenge := strings.TrimSpace(c.Query("login_challenge")); challenge != "" {
		vars["challenge"] = challenge
	}
	return c.Render("login.html", vars)
}

func (r *Router) Logout(c *fiber.Ctx) error {
	return r.redirectLogin(c)
}

func (r *Router) logout(c *fiber.Ctx) {
	sess, err := r.session(c)
	if err != nil {
		return
	}

	username := sess.Get(SessionKeyUsername)
	if username != nil {
		log.WithFields(log.Fields{
			"username": username,
			"ip":       RemoteIP(c),
			"path":     c.Path(),
		}).Info("User logging out")
	}

	if err := sess.Destroy(); err != nil {
		log.WithFields(log.Fields{
			"username": username,
			"ip":       RemoteIP(c),
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
	r.logAuthStep(c, "redirect_login", log.Fields{
		"redirect_reason": "logout_or_session_invalid",
		"redirect_to":     "/auth/login",
	})

	r.logout(c)

	if c.Get("HX-Request", "false") == "true" {
		c.Set("HX-Redirect", "/auth/login")
		return c.Status(fiber.StatusNoContent).SendString("")
	}

	return c.Redirect("/auth/login")
}

func (r *Router) RequireNoLogin(c *fiber.Ctx) error {
	if ok, _ := r.isLoggedIn(c); ok {
		r.logAuthStep(c, "redirect_already_authenticated", log.Fields{
			"redirect_reason": "session_already_authenticated",
			"redirect_to":     "/",
		})

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
			"ip":    RemoteIP(c),
			"error": err,
		}).Info("Login required and no authenticated session found.")
		return r.redirectLogin(c)
	}

	return c.Next()
}

func (r *Router) RequireMFA(c *fiber.Ctx) error {
	if !viper.GetBool("accounts.require_mfa") {
		return c.Next()
	}

	user := r.user(c)
	if !user.OTPOnly() {
		return c.Status(fiber.StatusUnauthorized).SendString(Translate("", "account.you_must_enable_two_factor_authentication_first"))
	}

	return c.Next()
}

func (r *Router) CheckUser(c *fiber.Ctx) error {
	r.logAuthStep(c, "check_user_start", nil)

	if authQueryHasCredentials(c) {
		return r.redirectCleanLogin(c, "credentials_in_query_string_on_post")
	}

	if password := strings.TrimSpace(c.FormValue("password")); password != "" {
		r.logAuthStep(c, "check_user_password_present", log.Fields{
			"action": "delegate_to_authenticate",
		})
		return r.Authenticate(c)
	}

	username := c.FormValue("username")

	if username == "" {
		r.logAuthStep(c, "check_user_missing_username", nil)
		return c.Status(fiber.StatusBadRequest).SendString(Translate("", "account.please_provide_username"))
	}

	if isBlocked(username) {
		log.WithFields(log.Fields{
			"username": username,
		}).Warn("AUDIT User account is blocked from logging in")
		r.metrics.totalFailedLogins.Inc()
		return c.Status(fiber.StatusUnauthorized).SendString(Translate("", "account.invalid_username"))
	}

	userRec, err := r.adminClient.UserShow(username)
	if err != nil {
		if ierr, ok := err.(*ipa.IpaError); ok && ierr.Code == 4001 {
			log.WithFields(log.Fields{
				"error":    ierr,
				"username": username,
			}).Warn("Username not found in FreeIPA")

			if !viper.GetBool("accounts.hide_invalid_username_error") {
				r.metrics.totalFailedLogins.Inc()
				return c.Status(fiber.StatusUnauthorized).SendString(Translate("", "account.invalid_username"))
			}
			userRec = new(ipa.User)
			userRec.Username = username
		} else {
			log.WithFields(log.Fields{
				"error":    err,
				"username": username,
			}).Error("Failed to fetch user info from FreeIPA")
			r.metrics.totalFailedLogins.Inc()
			return c.Status(fiber.StatusInternalServerError).SendString(Translate("", "account.fatal_system_error"))
		}
	}

	if userRec.Locked {
		log.WithFields(log.Fields{
			"username": username,
		}).Warn("AUDIT User account is locked in FreeIPA")
		r.metrics.totalFailedLogins.Inc()
		return c.Status(fiber.StatusUnauthorized).SendString(Translate("", "account.user_account_is_locked"))
	}

	log.WithFields(log.Fields{
		"username": username,
		"ip":       RemoteIP(c),
	}).Info("Login user attempt")

	r.logAuthStep(c, "check_user_show_password_step", log.Fields{
		"username": username,
	})

	vars := fiber.Map{
		"user":      userRec,
		"challenge": c.FormValue("challenge"),
	}

	return c.Render("login-form.html", vars)
}

func (r *Router) Authenticate(c *fiber.Ctx) error {
	r.logAuthStep(c, "authenticate_start", nil)

	if authQueryHasCredentials(c) {
		return r.redirectCleanLogin(c, "credentials_in_query_string_on_post")
	}

	username := c.FormValue("username")
	password := c.FormValue("password")
	challenge := c.FormValue("challenge")
	otp := c.FormValue("otp")

	if username == "" {
		return c.Status(fiber.StatusBadRequest).SendString(Translate("", "account.please_provide_username"))
	}

	if password == "" {
		return c.Status(fiber.StatusBadRequest).SendString(Translate("", "account.please_provide_password"))
	}

	if isBlocked(username) {
		log.WithFields(log.Fields{
			"username": username,
		}).Warn("AUDIT User account is blocked from logging in")
		r.metrics.totalFailedLogins.Inc()
		return c.Status(fiber.StatusUnauthorized).SendString(Translate("", "account.invalid_credentials"))
	}

	client := ipa.NewDefaultClient()
	err := client.RemoteLogin(username, password+otp)
	if err != nil {
		switch {
		case errors.Is(err, ipa.ErrExpiredPassword):
			log.WithFields(log.Fields{
				"username": username,
				"err":      err,
			}).Info("Password expired, redirecting to forgot password")

			target := fmt.Sprintf("/auth/forgotpw?expired=1&username=%s", url.QueryEscape(username))
			r.logAuthStep(c, "redirect_password_expired", log.Fields{
				"redirect_reason": "password_expired",
				"redirect_to":     target,
				"username":          username,
			})

			if c.Get("HX-Request", "false") == "true" {
				c.Set("HX-Redirect", target)
				return c.Status(fiber.StatusNoContent).SendString("")
			}

			return c.Redirect(target)
		default:
			log.WithFields(log.Fields{
				"username": username,
				"ip":       RemoteIP(c),
				"err":      err,
			}).Error("AUDIT Failed login attempt")
			r.metrics.totalFailedLogins.Inc()
			return c.Status(fiber.StatusUnauthorized).SendString(Translate("", "account.invalid_credentials"))
		}
	}

	_, err = client.Ping()
	if err != nil {
		log.WithFields(log.Fields{
			"username": username,
			"err":      err,
		}).Error("Failed to ping FreeIPA")
		r.metrics.totalFailedLogins.Inc()
		return c.Status(fiber.StatusUnauthorized).SendString(Translate("", "account.invalid_credentials"))
	}

	sess, err := r.session(c)
	if err != nil {
		r.logAuthStep(c, "authenticate_session_error", log.Fields{
			"error": err.Error(),
		})
		return err
	}

	err = sess.Regenerate()
	if err != nil {
		return err
	}

	sess.Set(SessionKeyAuthenticated, true)
	sess.Set(SessionKeyUsername, username)
	sess.Set(SessionKeySID, client.SessionID())

	if err := r.sessionSave(c, sess); err != nil {
		return err
	}

	r.logAuthStep(c, "authenticate_session_saved", log.Fields{
		"username":       username,
		"session_cookie": c.Cookies("session"),
		"ipa_session_id": client.SessionID(),
	})

	if viper.IsSet("hydra.admin_url") && challenge != "" {
		return r.LoginOAuthPost(username, challenge, c)
	}

	log.WithFields(log.Fields{
		"username": username,
		"ip":       RemoteIP(c),
	}).Info("AUDIT User logged in successfully")
	r.metrics.totalLogins.Inc()

	r.logAuthStep(c, "redirect_login_success", log.Fields{
		"redirect_reason": "authenticated",
		"redirect_to":     "/",
	})

	if c.Get("HX-Request", "false") == "true" {
		c.Set("HX-Redirect", "/")
		return c.Status(fiber.StatusNoContent).SendString("")
	}

	return c.Redirect("/")
}
