package rand

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

func GenerateSecureToken(length int) (string, error) {
	if length <= 0 {
		return "", errors.New("length must be greater than zero")
	}

	result := make([]byte, length)
	if _, err := rand.Read(result); err != nil {
		return "", fmt.Errorf("failed to generate random string: %w", err)
	}

	return hex.EncodeToString(result), nil
}
