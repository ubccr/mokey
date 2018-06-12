package util

import (
	"bytes"
	"encoding/base64"
	"image/png"

	"github.com/pquerna/otp"
	"github.com/ubccr/goipa"
)

func QRCode(otptoken *ipa.OTPToken) (string, error) {
	if otptoken == nil {
		return "", nil
	}

	key, err := otp.NewKeyFromURL(otptoken.URI)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	img, err := key.Image(250, 250)
	if err != nil {
		return "", err
	}

	png.Encode(&buf, img)
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
