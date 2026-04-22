package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError string
	}{
		{
			name:          "Success: Valid Authorization Header",
			headers:       http.Header{"Authorization": []string{"ApiKey secret-token-123"}},
			expectedKey:   "secret-token-123",
			expectedError: "",
		},
		{
			name:          "Error: Missing Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: "no authorization header included",
		},
		{
			name:          "Error: Malformed Header (No Space)",
			headers:       http.Header{"Authorization": []string{"ApiKeyNoSpace"}},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name:          "Error: Malformed Header (Wrong Prefix)",
			headers:       http.Header{"Authorization": []string{"Bearer token123"}},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name:          "Error: Empty Header Value",
			headers:       http.Header{"Authorization": []string{""}},
			expectedKey:   "",
			expectedError: "no authorization header included",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if tt.expectedError != "" {
				if err == nil || err.Error() != tt.expectedError {
					t.Errorf("GetAPIKey() error = %v, want %v", err, tt.expectedError)
					return
				}
			} else if err != nil {
				t.Errorf("GetAPIKey() unexpected error: %v", err)
				return
			}

			if key != tt.expectedKey {
				t.Errorf("GetAPIKey() key = %v, want %v", key, tt.expectedKey)
			}
		})
	}
}
