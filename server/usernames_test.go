package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ubccr/goipa"
)

func TestUsernameFromEmail(t *testing.T) {
	assert := assert.New(t)

	allowedDomains := map[string]string{
		"example.edu": "default",
		"example.com": "flast",
	}

	type testUsername struct {
		test   string
		result string
	}

	goodTests := []testUsername{
		testUsername{"user@example.edu", "user"},
		testUsername{"user123@example.edu", "user123"},
		testUsername{"user.test@example.edu", "user.test"},
		testUsername{"user-test@example.edu", "user-test"},
		testUsername{"user@test@example.edu", "usertest"},
		testUsername{"user+test@example.edu", "usertest"},
		testUsername{"first.last@example.com", "flast"},
		testUsername{".last@example.com", "last"},
	}

	for _, utest := range goodTests {
		user := &ipa.User{Email: utest.test}
		err := generateUsernameFromEmail(user, allowedDomains)
		if assert.NoError(err) {
			assert.Equal(utest.result, user.Username)
		}
	}

	badTests := []testUsername{
		testUsername{"user@invalidemail.edu", ""},
		testUsername{"@example.edu", ""},
	}

	for _, utest := range badTests {
		user := &ipa.User{Email: utest.test}
		err := generateUsernameFromEmail(user, allowedDomains)
		assert.Error(err)
	}

}
