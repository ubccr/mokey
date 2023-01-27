package server

import (
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	ipa "github.com/ubccr/goipa"
)

func (r *Router) SSHKeyList(c *fiber.Ctx) error {
	user := r.user(c)
	vars := fiber.Map{
		"user": user,
	}
	return c.Render("sshkey-list.html", vars)
}

func (r *Router) SSHKeyModal(c *fiber.Ctx) error {
	vars := fiber.Map{}
	return c.Render("sshkey-new.html", vars)
}

func (r *Router) SSHKeyAdd(c *fiber.Ctx) error {
	user := r.user(c)

	title := c.FormValue("title")
	key := c.FormValue("key")

	if key == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Please provide an ssh key")
	}

	authKey, err := ipa.NewSSHAuthorizedKey(key)
	if err != nil {
		log.WithFields(log.Fields{
			"username": user.Username,
			"err":      err,
		}).Error("Failed to add new ssh key")
		return c.Status(fiber.StatusBadRequest).SendString("Invalid ssh key")
	}

	if title != "" {
		// TODO validate title
		authKey.Comment = title
	}

	user.AddSSHAuthorizedKey(authKey)

	user, err = r.adminClient.UserMod(user)
	if err != nil {
		return err
	}

	c.Locals(ContextKeyUser, user)

	err = r.emailer.SendSSHKeyUpdatedEmail(true, user, c)
	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": user.Username,
		}).Error("Failed to send sshkey added email")
	}

	return r.SSHKeyList(c)
}

func (r *Router) SSHKeyRemove(c *fiber.Ctx) error {
	fp := c.FormValue("fp")
	user := r.user(c)

	user.RemoveSSHAuthorizedKey(fp)

	var err error
	user, err = r.adminClient.UserMod(user)
	if err != nil {
		return err
	}

	c.Locals(ContextKeyUser, user)

	err = r.emailer.SendSSHKeyUpdatedEmail(false, user, c)
	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": user.Username,
		}).Error("Failed to send sshkey removed email")
	}

	return r.SSHKeyList(c)
}
