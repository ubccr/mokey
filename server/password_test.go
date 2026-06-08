package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPasswordCheck(t *testing.T) {
	assert := assert.New(t)

	// Too short
	assert.Error(checkPassword("123", 8, 3))
	// Not enough classes
	assert.Error(checkPassword("123456789", 8, 3))
	// Not enough classes
	assert.Error(checkPassword("test1234", 8, 3))

	// Good
	assert.NoError(checkPassword("test!1234", 8, 3))

	// Per-user policy: engineering group requires 16 chars and 2 classes
	assert.Error(checkPassword("Short1!abc", 16, 2))
	assert.NoError(checkPassword("LongEnoughPass1!", 16, 2))
}
