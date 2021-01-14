package jwt

import (
	"encoding/base64"
)

//easyjson:json
type Claims struct {
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	ID        string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	Subject   string `json:"sub,omitempty"`
}

func (c *Claims) Encode() (string, error) {
	marshaled, err := c.MarshalJSON()
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(marshaled), nil
}

func (c *Claims) Decode(data []byte) error {
	dst := make([]byte, base64.RawURLEncoding.DecodedLen(len(data)))
	_, err := base64.RawURLEncoding.Decode(dst, data)
	if err != nil {
		return err
	}

	return c.UnmarshalJSON(dst)
}
