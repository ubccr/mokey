package server

const (
	CookieKeySession       = "mokey-sessck"
	CookieKeyState         = "state"
	CookieKeyAuthenticated = "authenticated"
	CookieKeySID           = "sid"
	CookieKeyUser          = "user"
	CookieKeyWYAF          = "wyaf"
	ContextKeyUser         = "user"
	ContextKeyApi          = "apikey"
	CSRFFieldName          = "auth_tok"
	TokenRegex             = `[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\-\_\.]+`
)
