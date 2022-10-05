package server

var Version = "dev"

const (
	SessionKeyAuthenticated = "authenticated"
	SessionKeySID           = "sid"
	SessionKeyUsername      = "user"
	ContextKeyUser          = "user"
	ContextKeyUsername      = "username"
	ContextKeyIPAClient     = "ipa"
	UserCategoryUnverified  = "mokey-user-unverified"
	TokenAccountVerify      = "verify"
	TokenPasswordReset      = "reset"
	TokenUsedPrefix         = "used-"
	TokenIssuedPrefix       = "issued-"
)
