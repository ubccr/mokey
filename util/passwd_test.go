package util

import (
	"testing"
)

func TestCheckPassword(t *testing.T) {

	ml := 8
	mc := 2

	good := []string{
		"6quegNabnod",
		"Knos2od-",
		"CryndIch#Of1",
		"aaa2349$",
		"x2aaa2~349",
	}

	for _, p := range good {
		if err := CheckPassword(p, ml, mc); err != nil {
			t.Errorf("Password check failed when should be good: %s", p)
		}
	}

	bad := []string{
		"   ",
		"a",
		"aaaaaaaaaa2",
		"ccc345np",
		"abasdfasdfasdf",
		"2229879asdf87978987",
		"ab2!",
	}

	for _, p := range bad {
		if err := CheckPassword(p, ml, mc); err == nil {
			t.Errorf("Password check passed when should have failed: %s", p)
		}
	}
}
