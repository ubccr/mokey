// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"errors"
	"fmt"
	"time"

	"github.com/tidwall/gjson"
)

// PasswordPolicyMaxLife returns the effective maximum password lifetime in days
// for the given user (via pwpolicy_show --user=...).
func (c *Client) PasswordPolicyMaxLife(username string) (int, error) {
	options := Options{}
	if username != "" {
		options["user"] = username
	}

	res, err := c.rpc("pwpolicy_show", []string{}, options)
	if err != nil {
		return 0, err
	}

	if res.Result == nil || len(res.Result.Data) == 0 {
		return 0, errors.New("ipa: empty password policy response")
	}

	policy := gjson.ParseBytes(res.Result.Data)
	maxLife := policy.Get("krbmaxpwdlife.0").Int()
	if maxLife == 0 {
		maxLife = policy.Get("krbmaxpwdlife").Int()
	}
	if maxLife <= 0 {
		return 0, fmt.Errorf("ipa: password policy has no max lifetime for user %s", username)
	}

	return int(maxLife), nil
}

// SetPasswordExpiration sets krbPasswordExpiration for a user.
func (c *Client) SetPasswordExpiration(username string, expires time.Time) error {
	options := Options{
		"password_expiration": expires.UTC().Format("2006-01-02 15:04:05Z"),
	}

	_, err := c.rpc("user_mod", []string{username}, options)
	return err
}

// RefreshPasswordExpiration sets krbPasswordExpiration to now plus the user's
// effective password policy max lifetime.
func (c *Client) RefreshPasswordExpiration(username string) error {
	maxLife, err := c.PasswordPolicyMaxLife(username)
	if err != nil {
		return err
	}

	expires := time.Now().UTC().Add(time.Duration(maxLife) * 24 * time.Hour)
	return c.SetPasswordExpiration(username, expires)
}

// ResetUserPassword sets a new password using ResetPassword followed by the
// self-service change_password endpoint. This avoids FreeIPA marking admin-set
// passwords as immediately expired.
func (c *Client) ResetUserPassword(username, newPassword, otpcode string) error {
	rand, err := c.ResetPassword(username)
	if err != nil {
		return err
	}

	return c.SetPassword(username, rand, newPassword, otpcode)
}
