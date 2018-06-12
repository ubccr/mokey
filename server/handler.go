package server

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
	"github.com/ubccr/mokey/model"
	"github.com/ubccr/mokey/util"
)

type Handler struct {
	db      model.Datastore
	client  *ipa.Client
	emailer *util.Emailer
}

func NewHandler(db model.Datastore) (*Handler, error) {
	h := &Handler{db: db}

	h.client = ipa.NewDefaultClient()

	err := h.client.LoginWithKeytab(viper.GetString("keytab"), viper.GetString("ktuser"))
	if err != nil {
		return nil, err
	}

	h.emailer, err = util.NewEmailer()
	if err != nil {
		return nil, err
	}

	h.client.StickySession(false)

	return h, nil
}

func (h *Handler) SetupRoutes(e *echo.Echo) {
	e.GET("/", LoginRequired(h.Index))
	e.GET("/auth/login", h.Login)
	e.POST("/auth/login", h.Login)
	e.GET("/auth/logout", h.Logout)
	e.GET("/auth/signup", h.Signup)
	e.POST("/auth/signup", h.CreateAccount)
	e.GET("/captcha/*.png", h.Captcha)
}

func (h *Handler) Index(c echo.Context) error {
	user := c.Get(ContextKeyUser)
	if user == nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user")
	}

	vars := map[string]interface{}{
		"user": user.(*ipa.UserRecord)}

	return c.Render(http.StatusOK, "index.html", vars)
}

func (h *Handler) NewAccountEmail(uid, email string) error {
	token, err := h.db.CreateToken(uid, email)
	if err != nil {
		return err
	}

	vars := map[string]interface{}{
		"uid":  uid,
		"link": fmt.Sprintf("%s/auth/setup/%s", viper.GetString("email_link_base"), h.db.SignToken(AccountSetupSalt, token.Token))}

	err = h.emailer.SendEmail(token.Email, fmt.Sprintf("[%s] New Account Setup", viper.GetString("email_prefix")), "setup-account.txt", vars)
	if err != nil {
		return err
	}

	err = h.db.RemoveAnswer(uid)
	if err != nil {
		return err
	}

	err = h.removeAllOTPTokens(uid)
	if err != nil {
		return err
	}

	return nil
}

func (h *Handler) removeAllOTPTokens(uid string) error {
	tokens, err := h.client.FetchOTPTokens(uid)
	if err != nil {
		return err
	}

	for _, t := range tokens {
		err = h.client.RemoveOTPToken(string(t.UUID))
		if err != nil {
			return err
		}
	}

	return nil
}
