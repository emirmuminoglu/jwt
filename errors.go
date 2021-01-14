package jwt

import "errors"

var (
	ErrMalformedToken = errors.New("malformed token")
	ErrInvalidSign    = errors.New("invalid sign")
	ErrWrongAlgorithm = errors.New("wrong algorithm")
	ErrExpiredToken   = errors.New("expired token")
)
