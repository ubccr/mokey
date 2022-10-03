package server

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	valid "github.com/asaskevich/govalidator"
	"github.com/spf13/viper"
	"github.com/ubccr/goipa"
)

var (
	ErrDomainNotAllowed = errors.New("Email domain not allowed")
	ErrInvalidUsername  = errors.New("Username is invalid. May only include letters, numbers, _, -, .")

	usernameRegx = regexp.MustCompile("^[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,31}$")
	rxUsername   = regexp.MustCompile("[^a-zA-Z0-9_.-]")
)

func defaultUsernameGenerator(username string) string {
	return rxUsername.ReplaceAllString(username, "")
}

func flastUsernameGenerator(username string) string {
	dot := strings.Index(username, ".")
	first, last := username[:dot], username[dot+1:]
	username = last
	if first != "" {
		username = string(first[0]) + last
	}
	return rxUsername.ReplaceAllString(username, "")
}

func generateUsernameFromEmail(user *ipa.User, allowedDomains map[string]string) error {
	at := strings.LastIndex(user.Email, "@")
	username, domain := user.Email[:at], strings.ToLower(user.Email[at+1:])

	if len(allowedDomains) == 0 {
		user.Username = defaultUsernameGenerator(username)
	} else {
		if _, ok := allowedDomains[domain]; !ok {
			return fmt.Errorf("%w: %s", ErrDomainNotAllowed, domain)
		}

		switch allowedDomains[domain] {
		case "flast":
			user.Username = flastUsernameGenerator(username)
		default:
			user.Username = defaultUsernameGenerator(username)
		}
	}

	return nil
}

func validateEmail(user *ipa.User, allowedDomains map[string]string) error {
	if !valid.IsEmail(user.Email) {
		return errors.New("Please provide a valid email address")
	}

	if len(allowedDomains) > 0 {
		at := strings.LastIndex(user.Email, "@")
		_, domain := user.Email[:at], strings.ToLower(user.Email[at+1:])

		if _, ok := allowedDomains[domain]; !ok {
			return fmt.Errorf("%w: %s", ErrDomainNotAllowed, domain)
		}
	}

	return nil
}

func validateUsername(user *ipa.User) error {
	allowedDomains := viper.GetStringMapString("accounts.allowed_domains")

	if err := validateEmail(user, allowedDomains); err != nil {
		return err
	}

	if viper.GetBool("accounts.username_from_email") {
		if err := generateUsernameFromEmail(user, allowedDomains); err != nil {
			return err
		}
	}

	if !usernameRegx.MatchString(user.Username) {
		return fmt.Errorf("%w: %s", ErrInvalidUsername, user.Username)
	}

	if valid.IsNumeric(user.Username) {
		return errors.New("Username must include at least one letter")
	}

	user.Username = strings.ToLower(user.Username)

	return nil
}
