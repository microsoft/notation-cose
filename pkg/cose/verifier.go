package cose

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/notaryproject/notation-go-lib/crypto/timestamp"
)

// maxTimestampAccuracy specifies the max acceptable accuracy for timestamp.
const maxTimestampAccuracy = time.Minute

// verifyTimestamp verifies the timestamp token and returns stamped time.
func verifyTimestamp(contentBytes, tokenBytes []byte, roots *x509.CertPool) (time.Time, error) {
	token, err := timestamp.ParseSignedToken(tokenBytes)
	if err != nil {
		return time.Time{}, err
	}
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := token.Verify(opts); err != nil {
		return time.Time{}, err
	}
	info, err := token.Info()
	if err != nil {
		return time.Time{}, err
	}
	if err := info.Verify(contentBytes); err != nil {
		return time.Time{}, err
	}
	stampedTime, accuracy := info.Timestamp()
	if accuracy > maxTimestampAccuracy {
		return time.Time{}, fmt.Errorf("max timestamp accuracy exceeded: %v", accuracy)
	}
	return stampedTime, nil
}
