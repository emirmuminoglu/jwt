package jwt

import "errors"

var (
	ErrMalformedToken = errors.New("malformed token")
	ErrInvalidClaims  = errors.New("invalid claims")
	ErrInvalidSign    = errors.New("invalid sign")
	ErrWrongAlgorithm = errors.New("wrong algorithm")
	ErrExpiredToken   = errors.New("expired token")
)
