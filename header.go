package jwt

import (
	"encoding/base64"
	"sync"
)

//easyjson:json
type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

func (h *Header) Encode() (string, error) {
	marshaled, err := h.MarshalJSON()
	if err != nil {
		return "", err
	}

	return base64.RawStdEncoding.EncodeToString(marshaled), nil
}

func (h *Header) Decode(data []byte) error {
	dst := make([]byte, base64.RawURLEncoding.DecodedLen(len(data)))
	_, err := base64.RawURLEncoding.Decode(dst, data)
	if err != nil {
		return err
	}

	return h.UnmarshalJSON(dst)
}

var (
	headerPool sync.Pool
	zeroHeader = &Header{}
)

func acquireHeader() *Header {
	v := headerPool.Get()
	if v == nil {
		return &Header{Type: "JWT"}
	}

	return v.(*Header)
}

func releaseHeader(h *Header) {
	*h = *zeroHeader
	headerPool.Put(h)
}
