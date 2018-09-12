package server

import (
	"errors"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
	log "github.com/sirupsen/logrus"
	"github.com/ubccr/goipa"
)

func (h *Handler) SSHPubKey(c echo.Context) error {
	user := c.Get(ContextKeyUser).(*ipa.UserRecord)
	client := c.Get(ContextKeyIPAClient).(*ipa.Client)

	sess, err := session.Get(CookieKeySession, c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get session")
	}

	vars := map[string]interface{}{
		"flashes": sess.Flashes(),
		"user":    user,
		"csrf":    c.Get("csrf").(string),
	}

	if c.Request().Method == "POST" {
		idx := c.FormValue("index")

		err = h.removeSSHPubKey(client, user, idx)
		if err != nil {
			vars["message"] = err.Error()
		} else {
			vars["message"] = "SSH Public Key Deleted"
		}
	}

	sess.Save(c.Request(), c.Response())
	return c.Render(http.StatusOK, "ssh-pubkey.html", vars)
}

func (h *Handler) NewSSHPubKey(c echo.Context) error {
	user := c.Get(ContextKeyUser).(*ipa.UserRecord)

	vars := map[string]interface{}{
		"user": user,
		"csrf": c.Get("csrf").(string),
	}

	return c.Render(http.StatusOK, "new-ssh-pubkey.html", vars)
}

func (h *Handler) AddSSHPubKey(c echo.Context) error {
	user := c.Get(ContextKeyUser).(*ipa.UserRecord)
	client := c.Get(ContextKeyIPAClient).(*ipa.Client)

	sess, err := session.Get(CookieKeySession, c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get session")
	}

	vars := map[string]interface{}{
		"user": user,
		"csrf": c.Get("csrf").(string),
	}

	pubKey := ""
	file, err := c.FormFile("key_file")
	if err == nil && file.Size > 0 {
		src, err := file.Open()
		if err != nil {
			log.WithFields(log.Fields{
				"user":  string(user.Uid),
				"error": err,
			}).Error("Failed to open multipart file upload")
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to open file")
		}
		defer src.Close()

		data, err := ioutil.ReadAll(src)
		if err != nil {
			log.WithFields(log.Fields{
				"user": string(user.Uid),
				"err":  err,
			}).Error("Failed to read ssh pub key file upload")
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to read file")
		}
		pubKey = string(data)
	} else {
		pubKey = c.FormValue("key")
	}

	err = addSSHPubKey(client, user, pubKey)
	if err == nil {
		sess.AddFlash("SSH Public Key Added")
		sess.Save(c.Request(), c.Response())
		return c.Redirect(http.StatusFound, Path("/sshpubkey"))
	}

	vars["message"] = err.Error()

	return c.Render(http.StatusOK, "new-ssh-pubkey.html", vars)
}

func addSSHPubKey(client *ipa.Client, user *ipa.UserRecord, pubKey string) error {
	if len(pubKey) == 0 {
		return errors.New("No ssh key provided. Please provide a valid ssh public key")
	}

	pubKeys := make([]string, len(user.SSHPubKeys))
	copy(pubKeys, user.SSHPubKeys)
	found := false
	for _, k := range pubKeys {
		if k == pubKey {
			found = true
		}
	}

	if found {
		return errors.New("ssh key already exists.")
	}

	pubKeys = append(pubKeys, pubKey)

	newFps, err := client.UpdateSSHPubKeys(string(user.Uid), pubKeys)
	if err != nil {
		if ierr, ok := err.(*ipa.IpaError); ok {
			// Raised when a parameter value fails a validation rule
			if ierr.Code == 3009 {
				return errors.New("Invalid ssh public key")
			}
		} else {
			log.WithFields(log.Fields{
				"error": err.Error(),
				"user":  string(user.Uid),
			}).Error("Ipa error when attempting to add new ssh public key")
			return errors.New("Fatal system error occured.")
		}
	}

	user.SSHPubKeys = pubKeys
	user.SSHPubKeyFps = newFps

	return nil
}

func (h *Handler) removeSSHPubKey(client *ipa.Client, user *ipa.UserRecord, idx string) error {
	index, err := strconv.Atoi(idx)
	if err != nil {
		return errors.New("Invalid ssh key provided")
	}
	if index < 0 || index > len(user.SSHPubKeys) {
		log.WithFields(log.Fields{
			"user":  string(user.Uid),
			"index": index,
		}).Error("Invalid ssh pub key index")
		return errors.New("Invalid ssh key provided")
	}

	pubKeys := make([]string, len(user.SSHPubKeys))
	copy(pubKeys, user.SSHPubKeys)

	// Remove key at index
	pubKeys = append(pubKeys[:index], pubKeys[index+1:]...)

	newFps, err := client.UpdateSSHPubKeys(string(user.Uid), pubKeys)
	if err != nil {
		log.WithFields(log.Fields{
			"user":  string(user.Uid),
			"index": index,
			"error": err,
		}).Error("Failed to delete ssh pub key")
		return errors.New("Fatal error removing ssh key. Please contact your administrator")
	}

	user.SSHPubKeys = pubKeys
	user.SSHPubKeyFps = newFps
	return nil
}
