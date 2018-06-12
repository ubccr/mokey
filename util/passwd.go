package util

import (
	"fmt"
	"regexp"
)

var (
	lower  = regexp.MustCompile(`[a-z]`)
	upper  = regexp.MustCompile(`[A-Z]`)
	number = regexp.MustCompile(`[0-9]`)
	marks  = regexp.MustCompile(`[^0-9a-zA-Z]`)
)

// Simple password checker to validate passwords before creating an account
func CheckPassword(pass string, minLength, minClasses int) error {
	l := len([]rune(pass))
	if l < minLength {
		return fmt.Errorf("Password does not conform to policy. Min length: %d", minLength)
	}

	numCategories := 0

	if lower.MatchString(pass) {
		numCategories++
	}
	if upper.MatchString(pass) {
		numCategories++
	}
	if number.MatchString(pass) {
		numCategories++
	}
	if marks.MatchString(pass) {
		numCategories++
	}

	repeated := 0
	for i := 0; i < l; i++ {
		count := 1
		for j := i + 1; j < l; j++ {
			if pass[i] != pass[j] {
				break
			}
			count++
		}

		if count > repeated {
			repeated = count
		}
	}

	if repeated > 1 {
		numCategories--
	}

	if numCategories < minClasses {
		return fmt.Errorf("Password does not conform to policy. Min character classes required: %d", minClasses)
	}

	return nil
}
