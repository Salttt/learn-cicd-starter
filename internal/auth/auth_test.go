package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Test case 1: No authorization header
	headers1 := http.Header{}
	key1, err1 := GetAPIKey(headers1)
	if err1 != ErrNoAuthHeaderIncluded {
		t.Errorf("Expected ErrNoAuthHeaderIncluded but got %v", err1)
	}
	if key1 != "" {
		t.Errorf("Expected empty key but got %s", key1)
	}

	// Test case 2: Malformed authorization header
	headers2 := http.Header{}
	headers2.Add("Authorization", "somekey")
	key2, err2 := GetAPIKey(headers2)
	if err2 == nil || err2.Error() != "malformed authorization header" {
		t.Errorf("Expected 'malformed authorization header' but got %v", err2)
	}
	if key2 != "" {
		t.Errorf("Expected empty key but got %s", key2)
	}

	// Test case 3: Valid authorization header
	headers3 := http.Header{}
	headers3.Add("Authorization", "ApiKey validkey123")
	key3, err3 := GetAPIKey(headers3)
	if err3 != nil {
		t.Errorf("Expected no error but got %v", err3)
	}
	if key3 != "validkey123" {
		t.Errorf("Expected 'validkey123' but got %s", key3)
	}
}
