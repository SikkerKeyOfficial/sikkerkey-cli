package client

import (
	"errors"
	"testing"
)

// The fallback cache leans entirely on IsUnavailable to decide when a cached
// value may stand in for the live server. The security-critical half is the
// exclusions: an authoritative answer (bad auth, revoked access, deleted secret)
// must never be reported as "unavailable", or the cache would defeat revocation.
func TestIsUnavailable(t *testing.T) {
	fallbackOK := []int{0, 502, 503, 504, 520, 521, 522, 523, 524, 525, 526, 527, 530}
	for _, code := range fallbackOK {
		if !IsUnavailable(&ApiError{StatusCode: code}) {
			t.Errorf("status %d should be treated as unavailable (cache may serve)", code)
		}
	}

	neverFallback := []int{200, 400, 401, 403, 404, 409, 429, 500, 501}
	for _, code := range neverFallback {
		if IsUnavailable(&ApiError{StatusCode: code}) {
			t.Errorf("status %d must NOT be treated as unavailable (authoritative answer)", code)
		}
	}

	// A non-ApiError (e.g. a JSON parse failure) is not an availability signal.
	if IsUnavailable(errors.New("some other error")) {
		t.Error("a plain error must not be treated as unavailable")
	}
}
