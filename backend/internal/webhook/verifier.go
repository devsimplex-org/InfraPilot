package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Verifier validates webhook signatures
type Verifier interface {
	Verify(payload []byte, signature string, secret string) error
	Provider() string
}

// ==================== GitHub Verifier ====================

type GitHubVerifier struct{}

func (v *GitHubVerifier) Verify(payload []byte, signature string, secret string) error {
	if signature == "" {
		return fmt.Errorf("missing X-Hub-Signature-256 header")
	}

	// GitHub sends: sha256=<hash>
	if !strings.HasPrefix(signature, "sha256=") {
		return fmt.Errorf("invalid signature format, expected sha256= prefix")
	}

	expectedSig := signature[7:] // Remove "sha256=" prefix

	// Compute HMAC-SHA256
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	computedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(computedSig), []byte(expectedSig)) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func (v *GitHubVerifier) Provider() string {
	return "github"
}

// ==================== GitLab Verifier ====================

type GitLabVerifier struct{}

func (v *GitLabVerifier) Verify(payload []byte, token string, secret string) error {
	if token == "" {
		return fmt.Errorf("missing X-Gitlab-Token header")
	}

	// GitLab uses a simple token comparison
	if token != secret {
		return fmt.Errorf("token verification failed")
	}

	return nil
}

func (v *GitLabVerifier) Provider() string {
	return "gitlab"
}

// ==================== Generic Verifier ====================

type GenericVerifier struct{}

func (v *GenericVerifier) Verify(payload []byte, signature string, secret string) error {
	if signature == "" {
		return fmt.Errorf("missing X-Webhook-Signature header")
	}

	// Generic uses HMAC-SHA256 like GitHub
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	computedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(computedSig), []byte(signature)) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func (v *GenericVerifier) Provider() string {
	return "generic"
}

// ==================== Verifier Factory ====================

func GetVerifier(provider string) (Verifier, error) {
	switch provider {
	case "github":
		return &GitHubVerifier{}, nil
	case "gitlab":
		return &GitLabVerifier{}, nil
	case "generic", "jenkins":
		return &GenericVerifier{}, nil
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}
