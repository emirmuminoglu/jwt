package jwt

import "hash"

type Algorithm struct {
	Name string
	Hash func() hash.Hash
}
