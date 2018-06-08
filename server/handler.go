package server

import (
	"net/http"

	"github.com/labstack/echo"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/model"
)

type Handler struct {
	db     model.Datastore
	client *ipa.Client
}

func NewHandler(db model.Datastore) (*Handler, error) {
	h := &Handler{db: db}

	h.client = ipa.NewDefaultClient()

	err := h.client.LoginWithKeytab(viper.GetString("keytab"), viper.GetString("ktuser"))
	if err != nil {
		return nil, err
	}

	h.client.StickySession(false)

	return h, nil
}

func (h *Handler) Index(c echo.Context) error {
	return c.Render(http.StatusOK, "index.html", nil)
}
