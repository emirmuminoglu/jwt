package jwt

import (
	"testing"
)

func Test_NewHS256Custom(t *testing.T) {

	claims := struct {
		IssuedAt int64  `json:"iat"`
		Subject  string `json:"sub"`
	}{
		Subject:  "1234567890",
		IssuedAt: 1516239022,
	}

	expected := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsInN1YiI6IjEyMzQ1Njc4OTAifQ.J3p7EuXSUS_3nmNgw9ZK0jJgdSEq5VOOJ52psItXEwI"
	key := []byte("your-256-bit-secret")

	token, err := NewHS256Custom(key, claims)
	if err != nil {
		t.Error(err)
	}

	println(string(token))

	if string(token) != expected {
		t.Fail()
	}
}

func Test_ParseHS256Custom(t *testing.T) {
	token := []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsInN1YiI6IjEyMzQ1Njc4OTAifQ.J3p7EuXSUS_3nmNgw9ZK0jJgdSEq5VOOJ52psItXEwI")
	malformedTokens := []string{
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsInN1YiI6IjEyMzQ1Njc4OTAifQ.J3p7EuXSUS_3nmNgw9ZK0jJgdSEq5VOOJ52psItXEw",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsInN1YiI6IjEyMzQ1Njc4OTAif.J3p7EuXSUS_3nmNgw9ZK0jJgdSEq5VOOJ52psItXEwI",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ.eyJpYXQiOjE1MTYyMzkwMjIsInN1YiI6IjEyMzQ1Njc4OTAifQ.J3p7EuXSUS_3nmNgw9ZK0jJgdSEq5VOOJ52psItXEwI",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsInN1YiI6IjEyMzQ1Njc4OTAifQ",
	}
	key := []byte("your-256-bit-secret")

	claims := &struct {
		IssuedAt int64  `json:"iat"`
		Subject  string `json:"sub"`
	}{}

	err := ParseHS256Custom(key, token, claims, func(v interface{}) bool {
		return true
	})

	if err != nil || claims.Subject != "1234567890" || claims.IssuedAt != 1516239022 {
		t.Fail()
	}

	for _, v := range malformedTokens {
		err = ParseHS256Custom(key, []byte(v), claims, func(v interface{}) bool {
			return true
		})

		if err == nil {
			t.Fail()
		}
	}
}
