package server

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	log "github.com/sirupsen/logrus"
)

func (r *Router) session(c *fiber.Ctx) (*session.Session, error) {
	sess, err := r.sessionStore.Get(c)
	if err != nil {
		log.WithFields(log.Fields{
			"path": c.Path(),
			"err":  err,
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
		}).Error("Failed to save session to storage")

		return err
	}

	return nil
}
