package rand

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_GenerateBase64(t *testing.T) {
	tests := []struct {
		name           string
		length         int
		hasErr         bool
		expectedLength int
	}{
		{
			name:           "generate base 64",
			length:         32,
			hasErr:         false,
			expectedLength: 64,
		},
		{
			name:   "generate with negative length",
			length: -16,
			hasErr: true,
		},
		{
			name:           "generate long base 64",
			length:         256,
			hasErr:         false,
			expectedLength: 512,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			result, err := GenerateSecureToken(test.length)
			if test.hasErr {
				require.Error(t, err)
				require.Empty(t, result)
				return
			}

			require.NoError(t, err)
			require.NotEmpty(t, result)
			require.Len(t, result, test.expectedLength)
		})
	}
}
