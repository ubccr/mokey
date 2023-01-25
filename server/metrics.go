package server

import (
	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
)

type Metrics struct {
	handler                       fasthttp.RequestHandler
	totalLogins                   prometheus.Counter
	totalFailedLogins             prometheus.Counter
	totalSignups                  prometheus.Counter
	totalPasswordResets           prometheus.Counter
	totalPasswordResetsSent       prometheus.Counter
	totalAccountVerifications     prometheus.Counter
	totalAccountVerificationsSent prometheus.Counter
}

func NewMetrics() *Metrics {
	m := &Metrics{
		totalLogins: promauto.NewCounter(prometheus.CounterOpts{
			Name: "mokey_logins_total",
			Help: "The total number of successful logins",
		}),
		totalFailedLogins: promauto.NewCounter(prometheus.CounterOpts{
			Name: "mokey_logins_failed_total",
			Help: "The total number of failed logins",
		}),
		totalSignups: promauto.NewCounter(prometheus.CounterOpts{
			Name: "mokey_signups_total",
			Help: "The total number of new accounts created",
		}),
		totalPasswordResets: promauto.NewCounter(prometheus.CounterOpts{
			Name: "mokey_password_reset_total",
			Help: "The total number of successfull password resets",
		}),
		totalPasswordResetsSent: promauto.NewCounter(prometheus.CounterOpts{
			Name: "mokey_password_reset_sent_total",
			Help: "The total number of password reset emails sent",
		}),
		totalAccountVerifications: promauto.NewCounter(prometheus.CounterOpts{
			Name: "mokey_account_verification_total",
			Help: "The total number of successfull account verifications",
		}),
		totalAccountVerificationsSent: promauto.NewCounter(prometheus.CounterOpts{
			Name: "mokey_account_verification_sent_total",
			Help: "The total number of account verification emails sent",
		}),
	}

	m.handler = fasthttpadaptor.NewFastHTTPHandler(promhttp.Handler())

	return m
}

func (m *Metrics) Handler(c *fiber.Ctx) error {
	m.handler(c.Context())
	return nil
}
