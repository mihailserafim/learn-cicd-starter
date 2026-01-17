package auth

import (
	"reflect"
	"testing"
	"net/http"
	"errors"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		wantAPIKey string
		wantErr    error
	}{
		{
			name: "Valid API Key",
			headers: map[string]string{
				"Authorization": "ApiKey valid-api-key",
			},
			wantAPIKey: "valid-api-key",
			wantErr:    nil,
		},
		{
			name: "No Authorization Header",
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			wantAPIKey: "",
			wantErr:    ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header",
			headers: map[string]string{
				"Authorization": "Bearer some-token",
			},
			wantAPIKey: "",
			wantErr:    errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpHeaders := make(http.Header)
			for k, v := range tt.headers {
				httpHeaders.Set(k, v)
			}

			gotAPIKey, gotErr := GetAPIKey(httpHeaders)

			if gotAPIKey != tt.wantAPIKey {
				t.Errorf("GetAPIKey() gotAPIKey = %v, want %v", gotAPIKey, tt.wantAPIKey)
			}
			if !reflect.DeepEqual(gotErr, tt.wantErr) {
				t.Errorf("GetAPIKey() gotErr = %v, want %v", gotErr, tt.wantErr)
			}
		})
	}
}