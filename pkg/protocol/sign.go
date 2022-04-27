package protocol

import "github.com/notaryproject/notation-go"

// SignRequest is the request to sign artifacts
type SignRequest struct {
	Version     string               `json:"version"`
	Descriptor  notation.Descriptor  `json:"descriptor"`
	SignOptions notation.SignOptions `json:"signOptions"`
	KMSProfile  KMSProfileSuite      `json:"kmsProfile"`
}
