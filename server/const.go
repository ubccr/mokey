package server

var Version = "dev"

const (
	CookieKeySession        = "mokey-sessck"
	CookieKeyState          = "state"
	SessionKeyAuthenticated = "authenticated"
	SessionKeySID           = "sid"
	SessionKeyUser          = "user"
	CookieKeyWYAF           = "wyaf"
	CookieKeyGlobus         = "globus"
	CookieKeyGlobusUsername = "globus_username"
	ContextKeyUser          = "user"
	ContextKeyIPAClient     = "ipa"
	UserCategoryUnverified  = "mokey-user-unverified"
	TokenAccountVerify      = "verify"
	TokenPasswordReset      = "reset"
	TokenUsedPrefix         = "used-"
	TokenIssuedPrefix       = "issued-"
)
