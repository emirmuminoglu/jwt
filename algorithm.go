package jwt

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

type Algorithm struct {
	Name string
	Hash func() hash.Hash
}

var (
	hs256Algo = &Algorithm{
		Name: "HS256",
		Hash: sha256.New,
	}

	hs512Algo = &Algorithm{
		Name: "HS512",
		Hash: sha512.New,
	}

	hs384Algo = &Algorithm{
		Name: "HS284",
		Hash: sha512.New384,
	}
)
