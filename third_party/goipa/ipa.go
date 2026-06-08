// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

// Package ipa is a Go client library for FreeIPA
package ipa

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-ini/ini"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
	log "github.com/sirupsen/logrus"
)

const (
	DefaultKerbConf   = "/etc/krb5.conf"
	IpaClientVersion  = "2.237"
	IpaDatetimeFormat = "20060102150405Z"
)

var (
	ipaDefaultHost    string
	ipaDefaultRealm   string
	ipaCertPool       *x509.CertPool
	ipaSessionPattern = regexp.MustCompile(`^ipa_session=([^;]+);`)

	// ErrPasswordPolicy is returned when a password does not conform to the password policy
	ErrPasswordPolicy = errors.New("password does not conform to policy")

	// ErrInvalidPassword is returned when a password is invalid
	ErrInvalidPassword = errors.New("invalid current password")

	// ErrExpiredPassword is returned when a password is expired
	ErrExpiredPassword = errors.New("password expired")

	// ErrUnauthorized is returned when user is not authorized
	ErrUnauthorized = errors.New("unauthorized")

	// ErrUserExists is returned when user account already exists
	ErrUserExists = errors.New("unauthorized")
)

// FreeIPA Client
type Client struct {
	host       string
	realm      string
	keyTab     string
	sessionID  string
	sticky     bool
	httpClient *http.Client
	krbClient  *client.Client
}

// FreeIPA api options map
type Options map[string]interface{}

// FreeIPA error
type IpaError struct {
	Message string
	Code    int
}

// Result returned from a FreeIPA JSON rpc call
type Result struct {
	Summary string          `json:"summary"`
	Value   interface{}     `json:"value"`
	Data    json.RawMessage `json:"result"`
}

// Response returned from a FreeIPA JSON rpc call
type Response struct {
	Error     *IpaError `json:"error"`
	ID        int       `json:"id"`
	Principal string    `json:"principal"`
	Version   string    `json:"version"`
	Result    *Result   `json:"result"`
}

func init() {
	// If ca.crt for ipa exists, use it as the cert pool
	// otherwise default to system root ca.
	pem, err := ioutil.ReadFile("/etc/ipa/ca.crt")
	if err == nil {
		ipaCertPool = x509.NewCertPool()
		if !ipaCertPool.AppendCertsFromPEM(pem) {
			ipaCertPool = nil
		}
	}

	// Load default IPA host
	cfg, err := ini.Load("/etc/ipa/default.conf")
	if err == nil {
		ipaServerURL, err := url.Parse(cfg.Section("global").Key("xmlrpc_uri").MustString("http://localhost"))
		if err == nil {
			ipaDefaultHost = ipaServerURL.Host
		}
		ipaDefaultRealm = cfg.Section("global").Key("realm").MustString("LOCAL")
	}
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 1 * time.Minute,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{RootCAs: ipaCertPool},
			DisableCompression:    false,
		},
	}
}

// New default IPA Client using host and realm from /etc/ipa/default.conf
func NewDefaultClient() *Client {
	return &Client{
		host:       ipaDefaultHost,
		realm:      ipaDefaultRealm,
		sticky:     true,
		httpClient: newHTTPClient(),
	}
}

// New default IPA Client with existing sessionID using host and realm from /etc/ipa/default.conf
func NewDefaultClientWithSession(sessionID string) *Client {
	return &Client{
		host:       ipaDefaultHost,
		realm:      ipaDefaultRealm,
		httpClient: newHTTPClient(),
		sticky:     true,
		sessionID:  sessionID,
	}
}

// New IPA Client with host and realm
func NewClient(host, realm string) *Client {
	return &Client{
		host:       host,
		realm:      realm,
		sticky:     true,
		httpClient: newHTTPClient(),
	}
}

// New IPA Client with host, realm and custom http client
func NewClientCustomHttp(host, realm string, httpClient *http.Client) *Client {
	return &Client{
		host:       host,
		realm:      realm,
		sticky:     true,
		httpClient: httpClient,
	}
}

func (e *IpaError) Error() string {
	return fmt.Sprintf("ipa: error %d - %s", e.Code, e.Message)
}

// Call FreeIPA API with method, params and options
func (c *Client) rpc(method string, params []string, options Options) (*Response, error) {
	if options == nil {
		options = Options{}
	}
	options["version"] = IpaClientVersion

	data := []interface{}{
		params,
		options,
	}

	payload := Options{
		"id":     0,
		"method": method,
		"params": data,
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	ipaUrl := fmt.Sprintf("https://%s/ipa/json", c.host)
	if len(c.sessionID) > 0 {
		ipaUrl = fmt.Sprintf("https://%s/ipa/session/json", c.host)
	}

	req, err := http.NewRequest("POST", ipaUrl, bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", fmt.Sprintf("https://%s/ipa/xml", c.host))

	if len(c.sessionID) > 0 {
		// If session is set, use the session id
		req.Header.Set("Cookie", fmt.Sprintf("ipa_session=%s", c.sessionID))
	} else if c.krbClient != nil {
		// use Kerberos auth (SPNEGO)
		spnego.SetSPNEGOHeader(c.krbClient, req, "")
	}

	if log.IsLevelEnabled(log.TraceLevel) {
		dump, _ := httputil.DumpRequestOut(req, true)
		log.Tracef("FreeIPA RPC request: %s", dump)
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("IPA RPC called failed with HTTP status code: %d", res.StatusCode)
	}

	if err = c.setSessionID(res); err != nil {
		return nil, err
	}

	rawJson, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	log.Tracef("FreeIPA JSON response: %s", string(rawJson))

	var ipaRes Response
	err = json.Unmarshal(rawJson, &ipaRes)
	if err != nil {
		return nil, err
	}

	if ipaRes.Error != nil {
		return nil, ipaRes.Error
	}

	return &ipaRes, nil
}

// Returns FreeIPA server hostname
func (c *Client) Host() string {
	return c.host
}

// Returns FreeIPA realm
func (c *Client) Realm() string {
	return c.realm
}

// Ping FreeIPA server to check connection
func (c *Client) Ping() (*Response, error) {
	res, err := c.rpc("ping", []string{}, nil)

	if err != nil {
		return nil, err
	}

	return res, nil
}

// Return current FreeIPA sessionID
func (c *Client) SessionID() string {
	return c.sessionID
}

// Clears out FreeIPA session id
func (c *Client) ClearSession() {
	c.sessionID = ""
}

// Set stick sessions.
func (c *Client) StickySession(enable bool) {
	c.sticky = enable
}

// Set FreeIPA sessionID from http response cookie
func (c *Client) setSessionID(res *http.Response) error {
	if !c.sticky {
		return nil
	}

	cookie := res.Header.Get("Set-Cookie")
	if len(cookie) == 0 {
		return nil
	}

	ipaSession := ""
	matches := ipaSessionPattern.FindStringSubmatch(cookie)
	if len(matches) == 2 {
		ipaSession = matches[1]
	}

	if len(ipaSession) == 32 || strings.HasPrefix(ipaSession, "MagBearerToken") {
		c.sessionID = ipaSession
	} else {
		return errors.New("invalid set-cookie header")
	}

	return nil
}

// Login to FreeIPA using web API with uid/passwd and set the FreeIPA session
// id on the client for subsequent requests.
func (c *Client) RemoteLogin(uid, passwd string) error {
	ipaUrl := fmt.Sprintf("https://%s/ipa/session/login_password", c.host)

	form := url.Values{"user": {uid}, "password": {passwd}}
	req, err := http.NewRequest("POST", ipaUrl, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", fmt.Sprintf("https://%s/ipa", c.host))

	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if log.IsLevelEnabled(log.TraceLevel) {
		dump, _ := httputil.DumpResponse(res, true)
		log.Tracef("FreeIPA RemoteLogin response: %s", dump)
	}

	if res.StatusCode == 401 && res.Header.Get("X-IPA-Rejection-Reason") == "password-expired" {
		return ErrExpiredPassword
	}

	if res.StatusCode == 401 && res.Header.Get("X-IPA-Rejection-Reason") == "invalid-password" {
		return ErrInvalidPassword
	}

	if res.StatusCode == 401 {
		return ErrUnauthorized
	}

	if res.StatusCode != 200 {
		return fmt.Errorf("IPA login failed with HTTP status code: %d", res.StatusCode)
	}

	if err = c.setSessionID(res); err != nil {
		return err
	}

	return nil
}

// Login to FreeIPA using local kerberos login username and password
func (c *Client) Login(username, password string) error {
	cfg, err := config.Load(DefaultKerbConf)
	if err != nil {
		return err
	}

	cl := client.NewWithPassword(username, c.realm, password, cfg)

	err = cl.Login()
	if err != nil {
		return err
	}

	c.krbClient = cl

	return nil
}

// Login to FreeIPA using local kerberos login with keytab and username
func (c *Client) LoginWithKeytab(ktab, username string) error {
	cfg, err := config.Load(DefaultKerbConf)
	if err != nil {
		return err
	}

	kt, err := keytab.Load(ktab)
	if err != nil {
		return err
	}

	cl := client.NewWithKeytab(username, c.realm, kt, cfg)

	err = cl.Login()
	if err != nil {
		return err
	}

	c.krbClient = cl

	return nil
}

// Login to FreeIPA using credentials cache
func (c *Client) LoginFromCCache(cpath string) error {
	cfg, err := config.Load(DefaultKerbConf)
	if err != nil {
		return err
	}

	ccache, err := credentials.LoadCCache(cpath)
	if err != nil {
		return err
	}

	cl, err := client.NewFromCCache(ccache, cfg, client.AssumePreAuthentication(true))
	if err != nil {
		return err
	}

	err = cl.Login()
	if err != nil {
		return err
	}

	c.krbClient = cl

	return nil
}

// Parse a FreeIPA datetime. Datetimes in FreeIPA are returned using a
// class-hint system. Values are stored as an array with a single element
// indicating the type and value, for example, '[{"__datetime__": "YYYY-MM-DDTHH:MM:SSZ"]}'
func ParseDateTime(str string) time.Time {
	dt, err := time.Parse(IpaDatetimeFormat, str)
	if err != nil {
		return time.Time{}
	}

	return dt
}
