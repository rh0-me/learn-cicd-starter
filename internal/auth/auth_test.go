package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		wantKey   string
		wantError error
	}{
		{
			name:      "missing Authorization header",
			headers:   http.Header{},
			wantKey:   "",
			wantError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed Authorization header (wrong scheme)",
			headers: http.Header{
				"Authorization": []string{"Bearer sometoken"},
			},
			wantKey:   "",
			wantError: ErrNoAuthHeaderIncluded, // will actually be a generic error
		},
		{
			name: "malformed Authorization header (no key)",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey:   "",
			wantError: nil, // also generic error
		},
		{
			name: "valid Authorization header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			wantKey:   "my-secret-key",
			wantError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)
			if gotKey != tt.wantKey {
				t.Errorf("expected key %q, got %q", tt.wantKey, gotKey)
			}
			if (err != nil && tt.wantError == nil) ||
				(err == nil && tt.wantError != nil) {
				t.Errorf("expected error %v, got %v", tt.wantError, err)
			}
			// if you want stricter matching on errors:
			if tt.wantError != nil && err != nil && err.Error() != tt.wantError.Error() {
				t.Errorf("expected error %v, got %v", tt.wantError, err)
			}
		})
	}
}

