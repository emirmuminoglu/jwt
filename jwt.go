package jwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"time"
)

var dot = []byte(".")

func New(key []byte, algo *Algorithm, claims *Claims) ([]byte, error) {
	var message []byte

	header := acquireHeader()
	defer releaseHeader(header)
	header.Algorithm = algo.Name

	encodedHeader, err := header.Encode()
	if err != nil {
		return nil, err
	}

	message = append(message, encodedHeader...)

	encodedClaims, err := claims.Encode()
	if err != nil {
		return nil, err
	}

	message = append(message, dot...)
	message = append(message, encodedClaims...)
	mac := hmac.New(algo.Hash, key)

	_, err = mac.Write(message)
	if err != nil {
		return nil, err
	}

	message = append(message, dot...)

	sign := mac.Sum(nil)

	encodedSign := base64.RawURLEncoding.EncodeToString(sign)

	return append(message, encodedSign...), nil
}

func ParseAndValidate(token, key []byte, algo *Algorithm, claims *Claims) error {
	header := acquireHeader()
	defer releaseHeader(header)
	sign, message, err := Parse(token, header, claims)
	if err != nil {
		return err
	}

	if header.Algorithm != algo.Name {
		return ErrWrongAlgorithm
	}

	err = Verify(algo, message, sign, key)
	if err != nil {
		return err
	}

	if claims.ExpiresAt < time.Now().Unix() {
		return ErrExpiredToken
	}

	return nil
}

func Verify(algo *Algorithm, message, sign, key []byte) error {
	mac := hmac.New(algo.Hash, key)
	_, err := mac.Write(message)
	if err != nil {
		return ErrInvalidSign
	}

	expected := mac.Sum(nil)

	decodedSign := make([]byte, base64.RawURLEncoding.DecodedLen(len(sign)))
	_, err = base64.RawURLEncoding.Decode(decodedSign, sign)
	if err != nil {
		return ErrInvalidSign
	}
	result := hmac.Equal(expected, decodedSign)
	if !result {
		return ErrInvalidSign
	}

	return nil
}

func Parse(token []byte, header *Header, claims *Claims) ([]byte, []byte, error) {
	splitted := bytes.Split(token, dot)
	if len(splitted) != 3 {
		return nil, nil, ErrMalformedToken
	}

	err := header.Decode(splitted[0])
	if err != nil {
		return nil, nil, ErrMalformedToken
	}

	err = claims.Decode(splitted[1])
	if err != nil {
		return nil, nil, ErrMalformedToken
	}

	dotted := append(splitted[0], dot...)
	dotted = append(dotted, splitted[1]...)

	return splitted[2], dotted, nil
}

func NewHS256(key []byte, claims *Claims) ([]byte, error) {
	return New(key, hs256Algo, claims)
}

func ParseHS256(key, token []byte, claims *Claims) error {
	return ParseAndValidate(token, key, hs256Algo, claims)
}

func NewHS512(key []byte, claims *Claims) ([]byte, error) {
	return New(key, hs512Algo, claims)
}

func ParseHS512(key, token []byte, claims *Claims) error {
	return ParseAndValidate(token, key, hs512Algo, claims)
}

func NewHS384(key []byte, claims *Claims) ([]byte, error) {
	return New(key, hs384Algo, claims)
}

func ParseHS384(key, token []byte, claims *Claims) error {
	return ParseAndValidate(token, key, hs384Algo, claims)

}
