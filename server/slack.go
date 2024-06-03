package server

import (
	log "github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"github.com/spf13/viper"
)

type SlackNotifier struct {
	client *slack.Client
}

func NewSlackNotifier() *SlackNotifier {
	token := viper.GetString("slack.token")
	if token == "" {
		return nil
	}
	return &SlackNotifier{
		client: slack.New(token),
	}
}

func (s *SlackNotifier) SendSlackMessage(email, message string) error {
	user, err := s.client.GetUserByEmail(email)
	if err != nil {
		return err
	}

	channelID, timestamp, err := s.client.PostMessage(
		user.ID,
		slack.MsgOptionText(message, false),
	)
	if err != nil {
		return err
	}

	log.Infof("Message successfully sent to channel %s at %s", channelID, timestamp)
	return nil
}
