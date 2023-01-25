package server

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestPasswordCheck(t *testing.T) {
	viper.Set("accounts.min_passwd_len", 8)
	viper.Set("accounts.min_passwd_classes", 3)

	assert := assert.New(t)

	// Too short
	assert.Error(checkPassword("123"))
	// Not enough classes
	assert.Error(checkPassword("123456789"))
	// Not enough classes
	assert.Error(checkPassword("test1234"))

	// Good
	assert.NoError(checkPassword("test!1234"))
}
