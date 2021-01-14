package jwt

import "testing"

func Test_NewHS256(t *testing.T) {
	expected := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsInN1YiI6IjEyMzQ1Njc4OTAifQ.J3p7EuXSUS_3nmNgw9ZK0jJgdSEq5VOOJ52psItXEwI"
	key := []byte("your-256-bit-secret")

	claims := &Claims{
		Subject:  "1234567890",
		IssuedAt: 1516239022,
	}

	token, err := NewHS256(key, claims)
	if err != nil {
		t.Error(err)
	}

	if string(token) != expected {
		t.Fail()
	}
}

func Test_ParseHS256(t *testing.T) {
	token := []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsInN1YiI6IjEyMzQ1Njc4OTAifQ.J3p7EuXSUS_3nmNgw9ZK0jJgdSEq5VOOJ52psItXEwI")
	malformedTokens := []string{
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsInN1YiI6IjEyMzQ1Njc4OTAifQ.J3p7EuXSUS_3nmNgw9ZK0jJgdSEq5VOOJ52psItXEw",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsInN1YiI6IjEyMzQ1Njc4OTAif.J3p7EuXSUS_3nmNgw9ZK0jJgdSEq5VOOJ52psItXEwI",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ.eyJpYXQiOjE1MTYyMzkwMjIsInN1YiI6IjEyMzQ1Njc4OTAifQ.J3p7EuXSUS_3nmNgw9ZK0jJgdSEq5VOOJ52psItXEwI",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsInN1YiI6IjEyMzQ1Njc4OTAifQ",
	}
	key := []byte("your-256-bit-secret")

	claims := new(Claims)

	err := ParseHS256(key, token, claims)
	if err != ErrExpiredToken {
		t.Fail()
	}

	for _, v := range malformedTokens {
		err = ParseHS256(key, []byte(v), claims)
		if err == nil {
			t.Fail()
		}
	}
}
