package server

import (
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/ubccr/goipa"
)

func (r *Router) SSHKeyList(c *fiber.Ctx) error {
	username := c.Locals(ContextKeyUser).(string)
	client := c.Locals(ContextKeyIPAClient).(*ipa.Client)

	user, err := client.UserShow(username)
	if err != nil {
		return err
	}

	vars := fiber.Map{
		"keys": user.SSHAuthKeys,
	}
	return c.Render("sshkey-list.html", vars)
}

func (r *Router) SSHKeyModal(c *fiber.Ctx) error {
	vars := fiber.Map{}
	return c.Render("sshkey-new.html", vars)
}

func (r *Router) SSHKeyAdd(c *fiber.Ctx) error {
	username := c.Locals(ContextKeyUser).(string)
	client := c.Locals(ContextKeyIPAClient).(*ipa.Client)

	title := c.FormValue("title")
	key := c.FormValue("key")

	if key == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Please provide an ssh key")
	}

	authKey, err := ipa.NewSSHAuthorizedKey(key)
	if err != nil {
		log.WithFields(log.Fields{
			"username": username,
			"err":      err,
		}).Error("Failed to add new ssh key")
		return c.Status(fiber.StatusBadRequest).SendString("Invalid ssh key")
	}

	if title != "" {
		// TODO validate title
		authKey.Comment = title
	}

	user, err := client.UserShow(username)
	if err != nil {
		return err
	}

	user.AddSSHAuthorizedKey(authKey)

	user, err = client.UserMod(user)
	if err != nil {
		return err
	}

	vars := fiber.Map{
		"keys": user.SSHAuthKeys,
	}

	return c.Render("sshkey-list.html", vars)
}

func (r *Router) SSHKeyRemove(c *fiber.Ctx) error {
	fp := c.FormValue("fp")
	client := c.Locals(ContextKeyIPAClient).(*ipa.Client)
	username := c.Locals(ContextKeyUser).(string)

	user, err := client.UserShow(username)
	if err != nil {
		return err
	}

	user.RemoveSSHAuthorizedKey(fp)

	user, err = client.UserMod(user)
	if err != nil {
		return err
	}

	vars := fiber.Map{
		"keys": user.SSHAuthKeys,
	}

	return c.Render("sshkey-list.html", vars)
}
