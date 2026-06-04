package server

import ipa "github.com/ubccr/goipa"

// userHasOTP reports whether the user authenticates with an OTP token (Password+OTP or OTP-only).
func userHasOTP(user *ipa.User) bool {
	for _, t := range user.AuthTypes {
		if t == "otp" {
			return true
		}
	}
	return false
}
