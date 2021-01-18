package jwt

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
)

type ValidatorFunction func(claims interface{}) bool

func NewWithCustom(key []byte, algo *Algorithm, claims interface{}) ([]byte, error) {
	var message []byte

	header := acquireHeader()
	defer releaseHeader(header)
	header.Algorithm = algo.Name

	encodedHeader, err := header.Encode()
	if err != nil {
		return nil, err
	}

	message = append(message, encodedHeader...)

	encodedClaims, err := encodeCustomClaims(claims)
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

func ParseAndValidateCustom(token, key []byte, algo *Algorithm, claims interface{}, validator ValidatorFunction) error {
	header := acquireHeader()
	defer releaseHeader(header)
	sign, message, err := ParseCustom(token, header, claims)
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

	if !validator(claims) {
		return ErrExpiredToken
	}

	return nil
}

func ParseCustom(token []byte, header *Header, claims interface{}) ([]byte, []byte, error) {
	splitted := bytes.Split(token, dot)
	if len(splitted) != 3 {
		return nil, nil, ErrMalformedToken
	}

	err := header.Decode(splitted[0])
	if err != nil {
		return nil, nil, ErrMalformedToken
	}

	err = decodeCustomClaims(splitted[1], claims)
	if err != nil {
		return nil, nil, ErrMalformedToken
	}

	dotted := append(splitted[0], dot...)
	dotted = append(dotted, splitted[1]...)

	return splitted[2], dotted, nil
}

func NewHS256Custom(key []byte, claims interface{}) ([]byte, error) {
	return NewWithCustom(key, hs256Algo, claims)
}

func ParseHS256Custom(key, token []byte, claims interface{}, validator ValidatorFunction) error {
	return ParseAndValidateCustom(token, key, hs256Algo, claims, validator)
}

func NewHS512Custom(key []byte, claims interface{}) ([]byte, error) {
	return NewWithCustom(key, hs512Algo, claims)
}

func ParseHS512Custom(key, token []byte, claims interface{}, validator ValidatorFunction) error {
	return ParseAndValidateCustom(token, key, hs512Algo, claims, validator)
}

func NewHS384Custom(key []byte, claims interface{}) ([]byte, error) {
	return NewWithCustom(key, hs384Algo, claims)
}

func ParseHS384Custom(key, token []byte, claims interface{}, validator ValidatorFunction) error {
	return ParseAndValidateCustom(token, key, hs384Algo, claims, validator)

}
