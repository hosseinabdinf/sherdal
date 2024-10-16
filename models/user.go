package models

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// User type
type user struct {
	secretKey *rlwe.SecretKey
	publicKey *rlwe.PublicKey
}

type User interface {
}
