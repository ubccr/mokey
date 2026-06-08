// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubccr/goipa"
)

func addTestUser(c *ipa.Client, username, password string) (*ipa.User, error) {
	user := *ipa.User{}
	user.Username = username
	user.First = gofakeit.FirstName()
	user.Last = gofakeit.LastName()
	rec, err := c.UserAdd(user, password != "")
	if err != nil {
		return nil, err
	}

	if password != "" {
		err = c.SetPassword(username, rec.RandomPassword, password, "")
		if err != nil {
			return nil, err
		}
	}

	return rec, nil
}

func TestUserShow(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	c, err := newTestClientCCache()
	require.NoError(err)

	rec, err := c.UserShow(TestEnvAdminUser)
	require.NoError(err)

	assert.Equalf(TestEnvAdminUser, rec.Username, "User username invalid")
}

func TestUserAuthTypes(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	c, err := newTestClientCCache()
	require.NoError(err)

	username := gofakeit.Username()

	_, err = addTestUser(c, username, "")
	require.NoErrorf(err, "Failed to add test user")

	err = c.SetAuthTypes(username, []string{"otp"})
	assert.NoErrorf(err, "Failed to set user auth type to otp only")

	rec, err := c.UserShow(username)
	require.NoErrorf(err, "Failed to fetch user")
	assert.Truef(rec.OTPOnly(), "User should be auth type otp only")

	err = c.SetAuthTypes(username, nil)
	assert.NoErrorf(err, "Failed to reset user auth types")

	err = c.UserDelete(false, false, username)
	assert.NoErrorf(err, "Failed to remove user")
}

func TestUserMod(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	c, err := newTestClientCCache()
	require.NoError(err)

	username := gofakeit.Username()
	email := gofakeit.Email()
	first := gofakeit.FirstName()
	last := gofakeit.LastName()
	home := "/home/" + username
	shell := "/bin/tcsh"

	rec, err := addTestUser(c, username, "")
	require.NoErrorf(err, "Failed to add test user")

	rec.Email = email
	rec.First = first
	rec.Last = last
	rec.HomeDir = home
	rec.Shell = shell

	rec, err = c.UserMod(rec)
	require.NoErrorf(err, "Failed to modify user")

	assert.Equalf(strings.ToLower(username), rec.Username, "User username invalid")
	assert.Equalf(email, rec.Email, "Email is invalid")
	assert.Equalf(first, rec.First, "First name is invalid")
	assert.Equalf(last, rec.Last, "Last name is invalid")
	assert.Equalf(home, rec.HomeDir, "Homedir is invalid")
	assert.Equalf(shell, rec.Shell, "Shell is invalid")

	err = c.UserDelete(false, false, username)
	assert.NoErrorf(err, "Failed to remove user")
}

func TestUserAdd(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	c, err := newTestClientCCache()
	require.NoError(err)

	user := *ipa.User{}
	user.Username = gofakeit.Username()
	user.Email = gofakeit.Email()
	user.First = gofakeit.FirstName()
	user.Last = gofakeit.LastName()
	user.Home = "/user/" + username
	user.Shell = "/bin/bash"
	password := gofakeit.Password(true, true, true, true, false, 16)

	rec, err := c.UserAddWithPassword(user, password)
	require.NoErrorf(err, "Failed to add user")

	assert.Equalf(strings.ToLower(user.Username), rec.Username, "User username invalid")
	assert.Equalf(user.Email, rec.Email, "Email is invalid")
	assert.Equalf(user.First, rec.First, "First name is invalid")
	assert.Equalf(user.Last, rec.Last, "Last name is invalid")
	assert.Equalf(user.HomeDir, rec.HomeDir, "Homedir is invalid")
	assert.Equalf(user.Shell, rec.Shell, "Shell is invalid")

	userClient := ipa.NewDefaultClient()
	err = userClient.RemoteLogin(user.Username, password)
	require.NoErrorf(err, "Failed to login as new user account")
	assert.NotEmptyf(c.SessionID(), "Missing sessionID for new user account")

	err = c.UserDelete(false, false, user.Username)
	assert.NoErrorf(err, "Failed to remove user")
}

func TestUserLock(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	c, err := newTestClientCCache()
	require.NoError(err)

	username := gofakeit.Username()
	password := gofakeit.Password(true, true, true, true, false, 16)

	rec, err := addTestUser(c, username, password)
	require.NoErrorf(err, "Failed to add test user")

	assert.Falsef(rec.Locked, "Account should not be disabled")

	err = c.UserDisable(username)
	assert.NoErrorf(err, "Failed to disable user")

	rec, err = c.UserShow(username)
	require.NoErrorf(err, "Failed to show user")

	assert.Truef(rec.Locked, "Account should be locked")

	userClient := ipa.NewDefaultClient()
	err = userClient.RemoteLogin(username, password)
	assert.Errorf(err, "User should not be able to login")

	err = c.UserEnable(username)
	assert.NoErrorf(err, "Failed to enable user")

	rec, err = c.UserShow(username)
	require.NoErrorf(err, "Failed to show user")

	assert.Falsef(rec.Locked, "Account should not be disabled")

	userClient = ipa.NewDefaultClient()
	err = userClient.RemoteLogin(username, password)
	assert.NoErrorf(err, "User should be able to login")

	err = c.UserDelete(false, false, username)
	assert.NoErrorf(err, "Failed to remove user")
}

func TestSSHKeys(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	c, err := newTestClientCCache()
	require.NoError(err)

	username := gofakeit.Username()
	key := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDVBSs8RP8KPbdMwOmuKgjScx301k1mBZTubfcJc7HKcJ19f1Z/eJ5y9R7LjhsK1WGn8ISRtP2c0NUNPWcZHdWzTv6m2AFL4qniXr2vvKcewq2fxy8uXnUSvS054wwFDW6trmWV1Vrrab0eXO9S7tGGLdx2ySQ8Bzfe8wY3M2/N1gd5dzGSVg3qFspgikTKjRt5rfaWoN+/OWLDg1HHEWjY0Hgqry1bJW3U83SlIi9+JwKW0zxunwImgFsI1xC15lf7X9LOE9e6XGT1km/NTPOqoAvaCCA0KyAK7P6cLjFVAA/k9UnC/QX6JKXoURFRdhPEdFqauF3Xw9rwDFCFkMUp test@localhost"
	fingerprint := "SHA256:9NiBLAynn/9d9lNcu/rOh5VXdXIJeA1oJDxfBGsI9xc"

	rec, err := addTestUser(c, username, "")
	require.NoErrorf(err, "Failed to add test user")

	authKey, _ := ipa.NewSSHAuthorizedKey(key)
	rec.AddSSHAuthorizedKey(authKey)

	rec, err = c.UserMod(rec)
	require.NoErrorf(err, "Failed to modify user")

	assert.Equalf(1, len(rec.SSHAuthKeys), "Invalid number of ssh keys")
	assert.Equalf(key, rec.SSHAuthKeys[0].String(), "SSH keys do not match")
	assert.Equalf(fingerprint, rec.SSHAuthKeys[0].Fingerprint, "SSH key fingerprints do not match")

	rec.RemoveSSHAuthorizedKey(authKey.Fingerprint)

	assert.Equalf(0, len(rec.SSHAuthKeys), "No keys should be found")

	rec, err = c.UserMod(rec)
	require.NoErrorf(err, "Failed to modify user")

	assert.Equalf(0, len(rec.SSHAuthKeys), "Failed to remove ssh key")

	err = c.UserDelete(false, false, username)
	assert.NoErrorf(err, "Failed to remove user")
}

func TestUserFind(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	c, err := newTestClientCCache()
	require.NoError(err)

	username := gofakeit.Username()
	userRec, err := addTestUser(c, username, "")
	require.NoErrorf(err, "Failed to add test user")

	users, err := c.UserFind(ipa.Options{
		"uid": username,
	})
	require.NoErrorf(err, "Failed to find users")

	assert.Lenf(users, 1, "Wrong number of users found")
	user := users[0]
	assert.Equalf(user.UUID, userRec.UUID, "UUIDs should be the same")
	assert.Equalf(user.Username, userRec.Username, "Usernames should be the same")
	assert.Equalf(user.Uid, userRec.Uid, "Uid's should be the same")

	err = c.UserDelete(false, false, username)
	assert.NoErrorf(err, "Failed to remove user")
}
