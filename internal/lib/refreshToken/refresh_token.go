package refreshToken

import (
	"auth-service/internal/lib/rand"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
)

func Generate() string {
	token, err := rand.GenerateSecureToken(32)
	if err != nil {
		log.Fatal(fmt.Errorf("error generating token: %w", err))
	}

	return token
}

func Hash(token string, hmacSecret []byte) string {
	h := hmac.New(sha256.New, hmacSecret)
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}
