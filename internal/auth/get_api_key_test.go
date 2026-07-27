package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantAPIKey string
		wantErr    error
	}{
		{
			name:       "returns error when no authorization header is included",
			headers:    http.Header{},
			wantAPIKey: "",
			wantErr:    ErrNoAuthHeaderIncluded,
		},
		{
			name: "returns error when authorization header is malformed (Bearer)",
			headers: http.Header{
				"Authorization": []string{"Bearer some_token"},
			},
			wantAPIKey: "",
			wantErr:    errors.New("malformed authorization header"),
		},
		{
			name: "returns error when authorization header has no key value",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantAPIKey: "",
			wantErr:    errors.New("malformed authorization header"),
		},
		{
			name: "returns API key when authorization header is valid",
			headers: http.Header{
				"Authorization": []string{"ApiKey my_api_key"},
			},
			wantAPIKey: "wrong_api_key",
			wantErr:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAPIKey, err := GetAPIKey(tt.headers)

			if gotAPIKey != tt.wantAPIKey {
				t.Errorf("GetAPIKey() gotAPIKey = %q, want %q", gotAPIKey, tt.wantAPIKey)
			}

			if tt.wantErr != nil {
				if err == nil || err.Error() != tt.wantErr.Error() {
					t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("GetAPIKey() unexpected error = %v", err)
			}
		})
	}
}