//go:build integration
// +build integration

package github

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestGetRepoRefFromPullRequest_Integration(t *testing.T) {
	// Runs against GitHub directly (no mocks). Requires a token with access to the repo.
	// Configure via env vars:
	//   GITHUB_TOKEN (required)
	//   GITHUB_OWNER (default: k8shell-io)
	//   GITHUB_REPO (default: identity)
	//   GITHUB_PR_NUMBER (default: 7)
	//   GITHUB_EXPECT_REF (optional: if set, assert exact branch name)

	token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		t.Skip("GITHUB_TOKEN not set; skipping integration test")
	}

	owner := strings.TrimSpace(os.Getenv("GITHUB_OWNER"))
	if owner == "" {
		owner = "k8shell-io"
	}

	repo := strings.TrimSpace(os.Getenv("GITHUB_REPO"))
	if repo == "" {
		repo = "identity"
	}

	prStr := strings.TrimSpace(os.Getenv("GITHUB_PR_NUMBER"))
	if prStr == "" {
		prStr = "7"
	}
	prNumber, err := strconv.Atoi(prStr)
	if err != nil {
		t.Fatalf("invalid GITHUB_PR_NUMBER %q: %v", prStr, err)
	}

	ref, err := getRepoRefFromPullRequest(owner, repo, prNumber, token)
	if err != nil {
		t.Fatalf("getRepoRefFromPullRequest(%s/%s #%d) error: %v", owner, repo, prNumber, err)
	}
	if strings.TrimSpace(ref) == "" {
		t.Fatalf("expected non-empty ref for %s/%s #%d", owner, repo, prNumber)
	}

	if want := strings.TrimSpace(os.Getenv("GITHUB_EXPECT_REF")); want != "" && ref != want {
		t.Fatalf("ref mismatch: got %q want %q", ref, want)
	}
}
