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
	"github.com/ubccr/mokey/model"
	"github.com/ubccr/mokey/util"
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
	pass := c.FormValue("password")
	pass2 := c.FormValue("password2")
	captchaID := c.FormValue("captcha_id")
	captchaSol := c.FormValue("captcha_sol")

	err := r.accountCreate(user, pass, pass2, captchaID, captchaSol)
	if err != nil {
		c.Append("HX-Trigger", "{\"reloadCaptcha\":\""+captcha.New()+"\"}")
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	return c.Render("signup-success.html", fiber.Map{})
}

// accountCreate does the work of validation and creating the account in FreeIPA
func (r *Router) accountCreate(user *ipa.User, pass, pass2, captchaID, captchaSol string) error {
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

	if pass == "" {
		return errors.New("Please enter a new password")
	}

	if pass2 == "" {
		return errors.New("Please confirm your new password")
	}

	if pass != pass2 {
		return errors.New("Password do not match. Please confirm your password.")
	}

	if err := util.CheckPassword(pass, viper.GetInt("min_passwd_len"), viper.GetInt("min_passwd_classes")); err != nil {
		return err
	}

	if len(captchaID) == 0 {
		return errors.New("Invalid captcha provided")
	}
	if len(captchaSol) == 0 {
		return errors.New("Please type in the numbers you see in the picture")
	}

	if !captcha.VerifyString(captchaID, captchaSol) {
		return errors.New("The numbers you typed in do not match the image")
	}

	homedir := filepath.Join(viper.GetString("default_homedir"), user.Username)

	userRec, err := r.adminClient.UserAdd(user.Username, user.Email, user.First, user.Last, homedir, viper.GetString("default_shell"), true)
	if err != nil {
		if ierr, ok := err.(*ipa.IpaError); ok {
			if ierr.Code == 4002 {
				return fmt.Errorf("Username already exists: %s", user.Username)
			} else {
				log.WithFields(log.Fields{
					"code": ierr.Code,
				}).Error("Failed to create account. Please contact system administrator")
			}
		}

		log.WithFields(log.Fields{
			"err":      err,
			"username": user.Username,
			"email":    user.Email,
			"first":    user.First,
			"last":     user.Last,
			"homedir":  homedir,
		}).Error("Failed to create user account")
		return errors.New("Failed to create account. Please contact system administrator")
	}

	log.WithFields(log.Fields{
		"username": user.Username,
		"email":    user.Email,
		"first":    user.First,
		"last":     user.Last,
		"homedir":  homedir,
	}).Warn("New user account created")

	// Set password
	err = r.adminClient.SetPassword(user.Username, userRec.RandomPassword, pass, "")
	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": user.Username,
			"email":    user.Email,
		}).Error("Failed to set password for user")

		// TODO: need to handle this case better
		return errors.New("There was a problem creating your account. Please contact the administrator")
	}

	log.WithFields(log.Fields{
		"username": user.Username,
	}).Warn("User password set successfully")

	// Disable new users until they have verified their email address
	err = r.adminClient.UserDisable(user.Username)
	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": user.Username,
		}).Error("Failed to disable user")

		// TODO: should we tell user about this? probably not?
	}

	// Send user an email to verify their account
	err = r.emailer.SendVerifyAccountEmail(user.Username, user.Email)
	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": user.Username,
			"email":    user.Email,
		}).Error("Failed to send new account email")

		// TODO: should we tell user about this?
	} else {
		log.WithFields(log.Fields{
			"username": user.Username,
			"email":    user.Email,
		}).Warn("New user account email sent successfully")
	}

	return nil
}

func (r *Router) AccountVerify(c *fiber.Ctx) error {
	token := c.Params("token")

	claims, err := model.ParseToken(token, viper.GetUint32("token_max_age"))
	if err != nil {
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	tokenUsed, err := r.storage.Get(token)
	if tokenUsed != nil {
		// Token already used
		log.WithFields(log.Fields{
			"username": claims.UserName,
			"email":    claims.Email,
		}).Warn("Attempt to re-use account verification token")
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	vars := fiber.Map{
		"claims": claims,
	}

	if c.Method() == fiber.MethodGet {
		return c.Render("verify-account.html", vars)
	}

	user, err := r.adminClient.UserShow(claims.UserName)
	if err != nil {
		log.WithFields(log.Fields{
			"username": claims.UserName,
			"email":    claims.Email,
			"err":      err,
		}).Error("Verifying account failed while fetching user from FreeIPA")
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to verify account please contact administrator")
	}

	if user.Locked {
		err := r.adminClient.UserEnable(claims.UserName)
		if err != nil {
			log.WithFields(log.Fields{
				"username": claims.UserName,
				"email":    claims.Email,
				"error":    err,
			}).Error("Verify account failed to enable user in FreeIPA")
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to verify account please contact administrator")
		}
	}

	r.storage.Set(token, []byte("true"), time.Until(time.Now().Add(time.Duration(viper.GetInt("token_max_age"))*time.Second)))

	return c.Render("verify-success.html", vars)
}
