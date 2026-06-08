// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

const globalPasswordPolicyCN = "global_policy"

func parsePasswordPolicyMaxLife(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, errors.New("ipa: empty password policy response")
	}

	policy := gjson.ParseBytes(data)
	maxLife := policy.Get("krbmaxpwdlife.0").Int()
	if maxLife == 0 {
		maxLife = policy.Get("krbmaxpwdlife").Int()
	}
	if maxLife <= 0 {
		return 0, errors.New("ipa: password policy has no max lifetime")
	}

	return int(maxLife), nil
}

func (c *Client) showPasswordPolicy(cn, username string) (int, error) {
	params := []string{}
	if cn != "" {
		params = []string{cn}
	}

	options := Options{}
	if username != "" {
		options["user"] = username
	}

	res, err := c.rpc("pwpolicy_show", params, options)
	if err != nil {
		return 0, err
	}

	if res.Result == nil {
		return 0, errors.New("ipa: empty password policy response")
	}

	return parsePasswordPolicyMaxLife(res.Result.Data)
}

// PasswordPolicyMaxLife returns the effective maximum password lifetime in days
// for the given user. Falls back to the global policy when no user-specific
// policy is configured.
func (c *Client) PasswordPolicyMaxLife(username string) (int, error) {
	if username != "" {
		maxLife, err := c.showPasswordPolicy("", username)
		if err == nil {
			return maxLife, nil
		}

		if ierr, ok := err.(*IpaError); ok && ierr.Code == 4001 {
			log.WithFields(log.Fields{
				"username": username,
				"error":    err,
			}).Debug("No user-specific password policy, falling back to global_policy")
		} else {
			return 0, err
		}
	}

	return c.showPasswordPolicy(globalPasswordPolicyCN, "")
}

// SetPasswordExpiration sets krbPasswordExpiration for a user.
func (c *Client) SetPasswordExpiration(username string, expires time.Time) error {
	options := Options{
		"password_expiration": expires.UTC().Format("2006-01-02 15:04:05Z"),
	}

	_, err := c.rpc("user_mod", []string{username}, options)
	if err == nil {
		return nil
	}

	options = Options{
		"krbpasswordexpiration": expires.UTC().Format(IpaDatetimeFormat),
	}

	_, err = c.rpc("user_mod", []string{username}, options)
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

	anon := &Client{
		host:       c.host,
		realm:      c.realm,
		httpClient: newHTTPClient(),
	}

	return anon.SetPassword(username, rand, newPassword, otpcode)
}
