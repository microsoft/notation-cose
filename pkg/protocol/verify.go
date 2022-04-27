package protocol

import "github.com/notaryproject/notation-go"

// VerifyRequest is the request to verify a signature.
type VerifyRequest struct {
	Version       string                 `json:"version"`
	Signature     []byte                 `json:"signature"`
	VerifyOptions notation.VerifyOptions `json:"verifyOptions"`
	KMSProfile    KMSProfileSuite        `json:"kmsProfile"`
}
