package refreshToken

import (
	"auth-service/internal/lib/rand"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func Generate() string {
	token, _ := rand.GenerateSecureToken(32)
	return token
}

func Hash(token string, hmacSecret []byte) string {
	h := hmac.New(sha256.New, hmacSecret)
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}
