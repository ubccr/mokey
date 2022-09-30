package server

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	valid "github.com/asaskevich/govalidator"
	"github.com/dchest/captcha"
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
)

func (r *Router) AccountSettings(c *fiber.Ctx) error {
	username := r.username(c)
	client := r.userClient(c)

	user, err := client.UserShow(username)
	if err != nil {
		return err
	}

	vars := fiber.Map{
		"user": user,
	}

	if c.Method() == fiber.MethodGet {
		return c.Render("account.html", vars)
	}

	user.First = c.FormValue("first")
	user.Last = c.FormValue("last")
	user.Mobile = c.FormValue("phone")

	userUpdated, err := client.UserMod(user)
	if err != nil {
		if ierr, ok := err.(*ipa.IpaError); ok {
			log.WithFields(log.Fields{
				"username": username,
				"message":  ierr.Message,
				"code":     ierr.Code,
			}).Error("Failed to update account settings")
			vars["message"] = ierr.Message
		} else {
			log.WithFields(log.Fields{
				"username": username,
				"error":    err.Error(),
			}).Error("Failed to update account settings")
			vars["message"] = "Fatal system error"
		}
	} else {
		vars["user"] = userUpdated
		vars["success"] = true
	}
	return c.Render("account.html", vars)
}

func (r *Router) AccountCreate(c *fiber.Ctx) error {
	if c.Method() == fiber.MethodGet {
		vars := fiber.Map{
			"captchaID": captcha.New(),
		}

		return c.Render("signup.html", vars)
	}

	user := &ipa.User{}
	user.Username = c.FormValue("username")
	user.Email = c.FormValue("email")
	user.First = c.FormValue("first")
	user.Last = c.FormValue("last")
	password := c.FormValue("password")
	passwordConfirm := c.FormValue("password2")
	captchaID := c.FormValue("captcha_id")
	captchaSol := c.FormValue("captcha_sol")

	err := r.accountCreate(user, password, passwordConfirm, captchaID, captchaSol)
	if err != nil {
		c.Append("HX-Trigger", "{\"reloadCaptcha\":\""+captcha.New()+"\"}")
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	// Send user an email to verify their account
	err = r.emailer.SendAccountVerifyEmail(user, c)
	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": user.Username,
			"email":    user.Email,
		}).Error("Failed to send new account email")
	} else {
		log.WithFields(log.Fields{
			"username": user.Username,
			"email":    user.Email,
		}).Info("New user account email sent successfully")
	}

	return c.Render("signup-success.html", fiber.Map{})
}

// accountCreate does the work of validation and creating the account in FreeIPA
func (r *Router) accountCreate(user *ipa.User, password, passwordConfirm, captchaID, captchaSol string) error {
	if !valid.IsEmail(user.Email) {
		return errors.New("Please provide a valid email address")
	}

	if len(user.Username) <= 1 || len(user.Username) > 50 {
		return errors.New("Please provide a username")
	}

	if valid.IsNumeric(user.Username) {
		return errors.New("Username must include at least one letter")
	}

	if !valid.IsAlphanumeric(user.Username) {
		return errors.New("Username must be alpha numeric")
	}

	if user.First == "" || len(user.First) > 150 {
		return errors.New("Please provide your first name")
	}

	if user.Last == "" || len(user.Last) > 150 {
		return errors.New("Please provide your last name")
	}

	if err := validatePassword(password, passwordConfirm); err != nil {
		return err
	}

	if err := r.verifyCaptcha(captchaID, captchaSol); err != nil {
		return err
	}

	user.HomeDir = filepath.Join(viper.GetString("default_homedir"), user.Username)
	user.Shell = viper.GetString("default_shell")
	user.Category = UserCategoryUnverified

	userRec, err := r.adminClient.UserAddWithPassword(user, password)
	if err != nil {
		switch {
		case errors.Is(err, ipa.ErrUserExists):
			return fmt.Errorf("Username already exists: %s", user.Username)
		default:
			log.WithFields(log.Fields{
				"err":      err,
				"username": user.Username,
				"email":    user.Email,
				"first":    user.First,
				"last":     user.Last,
				"homedir":  user.HomeDir,
			}).Error("Failed to create user account")
			return errors.New("Failed to create account. Please contact system administrator")
		}
	}

	log.WithFields(log.Fields{
		"username": userRec.Username,
		"email":    userRec.Email,
		"first":    userRec.First,
		"last":     userRec.Last,
		"homedir":  userRec.HomeDir,
	}).Warn("New user account created")

	// Disable new users until they have verified their email address
	err = r.adminClient.UserDisable(userRec.Username)
	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": userRec.Username,
		}).Error("Failed to disable user")

		// TODO: should we tell user about this? probably not?
	}

	return nil
}

func (r *Router) AccountVerify(c *fiber.Ctx) error {
	token := c.Params("token")

	claims, err := ParseToken(token, r.storage)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Debug("Invalid account verify token")
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	vars := fiber.Map{
		"claims": claims,
	}

	if c.Method() == fiber.MethodGet {
		return c.Render("verify-account.html", vars)
	}

	user, err := r.adminClient.UserShow(claims.Username)
	if err != nil {
		log.WithFields(log.Fields{
			"username": claims.Username,
			"email":    claims.Email,
			"err":      err,
		}).Error("Verifying account failed while fetching user from FreeIPA")
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to verify account please contact administrator")
	}

	if user.Locked {
		err := r.adminClient.UserEnable(claims.Username)
		if err != nil {
			log.WithFields(log.Fields{
				"username": claims.Username,
				"email":    claims.Email,
				"error":    err,
			}).Error("Verify account failed to enable user in FreeIPA")
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to verify account please contact administrator")
		}
	}

	// User is now verified so unset category
	if user.Category == UserCategoryUnverified {
		user.Category = ""

		_, err = r.adminClient.UserMod(user)
		if err != nil {
			log.WithFields(log.Fields{
				"username": claims.Username,
				"email":    claims.Email,
				"error":    err,
			}).Error("Verify account failed to modify user category in FreeIPA")
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to verify account please contact administrator")
		}
	}

	r.storage.Set(TokenUsedPrefix+token, []byte("true"), time.Until(claims.Timestamp.Add(time.Duration(viper.GetInt("token_max_age"))*time.Second)))

	return c.Render("verify-success.html", vars)
}

func (r *Router) AccountVerifyResend(c *fiber.Ctx) error {
	if c.Method() == fiber.MethodGet {
		vars := fiber.Map{
			"captchaID": captcha.New(),
		}

		return c.Render("account-verify-forgot.html", vars)
	}

	err := r.verifyCaptcha(c.FormValue("captcha_id"), c.FormValue("captcha_sol"))
	if err != nil {
		c.Append("HX-Trigger", "{\"reloadCaptcha\":\""+captcha.New()+"\"}")
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	username := c.FormValue("username")

	user, err := r.adminClient.UserShow(username)
	if err != nil {
		log.WithFields(log.Fields{
			"username": username,
			"err":      err,
		}).Warn("Account verify attempt for unknown username")
		return c.Render("account-verify-forgot-success.html", fiber.Map{})
	}

	if !user.Locked {
		log.WithFields(log.Fields{
			"username": username,
		}).Warn("Account verify resend attempt for active user")
		return c.Render("account-verify-forgot-success.html", fiber.Map{})
	}

	if user.Category != UserCategoryUnverified {
		log.WithFields(log.Fields{
			"username": username,
		}).Warnf("Refusing to send account verify email. Invalid user category")
		return c.Render("account-verify-forgot-success.html", fiber.Map{})
	}

	// Resend user an email to verify their account
	err = r.emailer.SendAccountVerifyEmail(user, c)
	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": user.Username,
			"email":    user.Email,
		}).Error("Failed to re-send verify account email")
	} else {
		log.WithFields(log.Fields{
			"username": user.Username,
			"email":    user.Email,
		}).Info("Verify user account email sent successfully")
	}

	return c.Render("account-verify-forgot-success.html", fiber.Map{})
}
