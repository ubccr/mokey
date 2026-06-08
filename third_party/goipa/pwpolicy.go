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

// PasswordPolicy holds the effective password policy for a user.
type PasswordPolicy struct {
	CN          string
	MaxLifeDays int
	MinLength   int
	MinClasses  int
}

func policyInt(policy gjson.Result, paths ...string) int {
	for _, path := range paths {
		if v := policy.Get(path).Int(); v > 0 {
			return int(v)
		}
	}
	return 0
}

func parsePasswordPolicy(data []byte) (*PasswordPolicy, error) {
	if len(data) == 0 {
		return nil, errors.New("ipa: empty password policy response")
	}

	policy := gjson.ParseBytes(data)
	pp := &PasswordPolicy{
		CN:          policy.Get("cn.0").String(),
		MaxLifeDays: policyInt(policy, "krbmaxpwdlife.0", "krbmaxpwdlife", "krbMaxPwdLife.0", "krbMaxPwdLife"),
		MinLength:   policyInt(policy, "krbpwdminlength.0", "krbpwdminlength", "krbPwdMinLength.0", "krbPwdMinLength"),
		MinClasses:  policyInt(policy, "krbpwdmindiffchars.0", "krbpwdmindiffchars", "krbPwdMinDiffChars.0", "krbPwdMinDiffChars"),
	}

	if pp.MinLength == 0 && pp.MinClasses == 0 && pp.MaxLifeDays == 0 {
		return nil, errors.New("ipa: password policy has no usable settings")
	}

	return pp, nil
}

func parsePasswordPolicyFromResults(data []byte, preferCN string) (*PasswordPolicy, error) {
	if len(data) == 0 {
		return nil, errors.New("ipa: empty password policy response")
	}

	policies := gjson.ParseBytes(data)
	if !policies.IsArray() {
		return parsePasswordPolicy(data)
	}

	var fallback *PasswordPolicy
	policies.ForEach(func(_, policy gjson.Result) bool {
		pp, err := parsePasswordPolicy([]byte(policy.Raw))
		if err != nil {
			return true
		}
		cn := policy.Get("cn.0").String()
		if cn == preferCN || (preferCN == "" && cn == globalPasswordPolicyCN) {
			fallback = pp
			return false
		}
		if fallback == nil {
			fallback = pp
		}
		return true
	})

	if fallback == nil {
		return nil, errors.New("ipa: password policies found but none define usable settings")
	}

	return fallback, nil
}

func (c *Client) fetchPasswordPolicy(cn, username string) (*PasswordPolicy, error) {
	params := []string{}
	if cn != "" {
		params = []string{cn}
	}

	options := Options{"all": true}
	if username != "" {
		options["user"] = username
	}

	res, err := c.rpc("pwpolicy_show", params, options)
	if err != nil {
		return nil, err
	}

	if res.Result == nil {
		return nil, errors.New("ipa: empty password policy response")
	}

	return parsePasswordPolicy(res.Result.Data)
}

func (c *Client) findPasswordPolicy() (*PasswordPolicy, error) {
	res, err := c.rpc("pwpolicy_find", []string{""}, Options{"all": true})
	if err != nil {
		return nil, err
	}

	if res.Result == nil || len(res.Result.Data) == 0 {
		return nil, errors.New("ipa: no password policies found")
	}

	return parsePasswordPolicyFromResults(res.Result.Data, globalPasswordPolicyCN)
}

func isPasswordPolicyNotFound(err error) bool {
	if ierr, ok := err.(*IpaError); ok && ierr.Code == 4001 {
		return true
	}
	return false
}

// PasswordPolicyForUser returns the effective password policy for a user.
func (c *Client) PasswordPolicyForUser(username string) (*PasswordPolicy, error) {
	var attempts []func() (*PasswordPolicy, error)

	if username != "" {
		attempts = append(attempts, func() (*PasswordPolicy, error) {
			return c.fetchPasswordPolicy("", username)
		})
	}

	attempts = append(attempts,
		func() (*PasswordPolicy, error) { return c.fetchPasswordPolicy("", "") },
		func() (*PasswordPolicy, error) { return c.fetchPasswordPolicy(globalPasswordPolicyCN, "") },
		func() (*PasswordPolicy, error) { return c.findPasswordPolicy() },
	)

	var lastErr error
	for _, attempt := range attempts {
		pp, err := attempt()
		if err == nil {
			return pp, nil
		}
		lastErr = err
		if !isPasswordPolicyNotFound(err) {
			log.WithFields(log.Fields{
				"username": username,
				"error":    err,
			}).Debug("Password policy lookup attempt failed")
		}
	}

	return nil, lastErr
}

// PasswordPolicyMaxLife returns the effective maximum password lifetime in days
// for the given user.
func (c *Client) PasswordPolicyMaxLife(username string) (int, error) {
	pp, err := c.PasswordPolicyForUser(username)
	if err != nil {
		return 0, err
	}
	if pp.MaxLifeDays <= 0 {
		return 0, errors.New("ipa: password policy has no max lifetime")
	}
	return pp.MaxLifeDays, nil
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

// ResetUserPassword sets a new password using ResetPassword followed by the
// self-service change_password endpoint (unauthenticated HTTP). This avoids
// FreeIPA marking admin-set passwords as immediately expired.
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
