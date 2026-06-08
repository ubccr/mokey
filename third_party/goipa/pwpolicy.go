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

func (c *Client) findPasswordPolicyMaxLife() (int, error) {
	res, err := c.rpc("pwpolicy_find", []string{""}, Options{})
	if err != nil {
		return 0, err
	}

	if res.Result == nil || len(res.Result.Data) == 0 {
		return 0, errors.New("ipa: no password policies found")
	}

	policies := gjson.ParseBytes(res.Result.Data)
	if !policies.IsArray() {
		return parsePasswordPolicyMaxLife(res.Result.Data)
	}

	var fallback int
	policies.ForEach(func(_, policy gjson.Result) bool {
		ml := policy.Get("krbmaxpwdlife.0").Int()
		if ml == 0 {
			ml = policy.Get("krbmaxpwdlife").Int()
		}
		if ml <= 0 {
			return true
		}

		cn := policy.Get("cn.0").String()
		if cn == globalPasswordPolicyCN {
			fallback = int(ml)
			return false
		}
		if fallback == 0 {
			fallback = int(ml)
		}
		return true
	})

	if fallback <= 0 {
		return 0, errors.New("ipa: password policies found but none define max lifetime")
	}

	return fallback, nil
}

func isPasswordPolicyNotFound(err error) bool {
	if ierr, ok := err.(*IpaError); ok && ierr.Code == 4001 {
		return true
	}
	return false
}

// PasswordPolicyMaxLife returns the effective maximum password lifetime in days
// for the given user.
func (c *Client) PasswordPolicyMaxLife(username string) (int, error) {
	var attempts []func() (int, error)

	if username != "" {
		attempts = append(attempts, func() (int, error) {
			return c.showPasswordPolicy("", username)
		})
	}

	attempts = append(attempts,
		func() (int, error) { return c.showPasswordPolicy("", "") },
		func() (int, error) { return c.showPasswordPolicy(globalPasswordPolicyCN, "") },
		func() (int, error) { return c.findPasswordPolicyMaxLife() },
	)

	var lastErr error
	for _, attempt := range attempts {
		maxLife, err := attempt()
		if err == nil {
			return maxLife, nil
		}
		lastErr = err
		if !isPasswordPolicyNotFound(err) {
			log.WithFields(log.Fields{
				"username": username,
				"error":    err,
			}).Debug("Password policy lookup attempt failed")
		}
	}

	return 0, lastErr
}

func (c *Client) resolvePasswordMaxLife(username string) (int, error) {
	maxLife, err := c.PasswordPolicyMaxLife(username)
	if err == nil {
		return maxLife, nil
	}

	if c.PasswordMaxLifeFallback > 0 {
		log.WithFields(log.Fields{
			"username": username,
			"days":     c.PasswordMaxLifeFallback,
			"error":    err,
		}).Warn("Using configured accounts.password_max_life_days fallback for password expiration")
		return c.PasswordMaxLifeFallback, nil
	}

	return 0, err
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

	log.WithFields(log.Fields{
		"username": username,
		"error":    err,
	}).Debug("password_expiration user_mod failed, trying krbpasswordexpiration attribute")

	options = Options{
		"krbpasswordexpiration": expires.UTC().Format(IpaDatetimeFormat),
	}

	_, err = c.rpc("user_mod", []string{username}, options)
	return err
}

// RefreshPasswordExpiration sets krbPasswordExpiration to now plus the user's
// effective password policy max lifetime.
func (c *Client) RefreshPasswordExpiration(username string) error {
	maxLife, err := c.resolvePasswordMaxLife(username)
	if err != nil {
		return err
	}

	expires := time.Now().UTC().Add(time.Duration(maxLife) * 24 * time.Hour)
	if err := c.SetPasswordExpiration(username, expires); err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"username": username,
		"expires":  expires.UTC().Format(time.RFC3339),
		"maxlife":  maxLife,
	}).Info("Refreshed krbPasswordExpiration after password reset")

	return nil
}

// ResetUserPassword sets a new password using ResetPassword followed by passwd
// with the temporary random password as current_password. This clears FreeIPA's
// "administratively set password is expired" state and applies password policy.
func (c *Client) ResetUserPassword(username, newPassword, otpcode string) error {
	rand, err := c.ResetPassword(username)
	if err != nil {
		return err
	}

	return c.ChangePassword(username, rand, newPassword, otpcode)
}
