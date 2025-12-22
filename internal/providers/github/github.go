package github

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/k8shell-io/identity/internal/common"
)

const (
	GITHUB_ADDRESS          = "https://github.com"
	IDENTITY_USERAGENT      = "k8shell-identity/1.0"
	GITHUB_PUBLIC_USER_URL  = "https://api.github.com/users/%s"
	GITHUB_USER_URL         = "https://api.github.com/user"
	GITHUB_KEYS_URL         = "https://api.github.com/users/%s/keys"
	GITHUB_EMAILS_URL       = "https://api.github.com/user/emails"
	GITHUB_DEVICECODE_URL   = "https://github.com/login/device/code"
	GITHUB_ACCESSTOKEN_URL  = "https://github.com/login/oauth/access_token"
	GITHUB_FILE_CONTENT_URL = "https://api.github.com/repos/%s/%s/contents/%s"
	GITHUB_REPO_URL         = "https://api.github.com/repos/%s/%s"
	GITHUB_REF_URL          = "https://api.github.com/repos/%s/%s/git/ref/%s"
)

type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	Error       string `json:"error,omitempty"`
}

// GitHubRepo represents the GitHub repository response
type GitHubRepo struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Owner    struct {
		Login string `json:"login"`
	} `json:"owner"`
	Private     bool   `json:"private"`
	HTMLURL     string `json:"html_url"`
	Description string `json:"description"`
}

// FileContent represents the GitHub file content response
type FileContent struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
	Size     int    `json:"size"`
	Name     string `json:"name"`
	Path     string `json:"path"`
}

// GitRef represents the GitHub Git reference response
type GitRef struct {
	Ref    string `json:"ref"`
	NodeID string `json:"node_id"`
	URL    string `json:"url"`
	Object struct {
		SHA  string `json:"sha"`
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"object"`
}

func MakeRequest(client *http.Client, method string, url string, accessToken string,
	errNotOk bool) (any, int, error) {

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	req.Header.Set("User-Agent", IDENTITY_USERAGENT)

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to make request to GitHub API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK && errNotOk {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, resp.StatusCode, fmt.Errorf("request failed: status code: %d: %w",
				resp.StatusCode, ErrUnauthorized)
		}
		return nil, resp.StatusCode,
			fmt.Errorf("request failed: status code: %d, response: %s", resp.StatusCode, body)
	}
	var response any
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, resp.StatusCode,
			fmt.Errorf("failed to unmarshal response: %w", err)
	}

	resourceMap, err := common.ToJSON(response)
	if err != nil {
		return nil, resp.StatusCode,
			fmt.Errorf("failed to convert GitHub API response to map: %w", err)
	}

	return resourceMap, resp.StatusCode, nil
}

func getDeviceCode(client *http.Client, clientId string, scopes []string) (*DeviceCodeResponse, error) {
	data := url.Values{}
	data.Set("client_id", clientId)
	data.Set("scope", strings.Join(scopes, " "))

	req, err := http.NewRequest("POST", GITHUB_DEVICECODE_URL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", IDENTITY_USERAGENT)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected response: %s\n%s", resp.Status, string(body))
	}

	var result DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

func getAccessToken(client *http.Client, clientId, deviceCode string) (*AccessTokenResponse, error) {
	data := url.Values{}
	data.Set("client_id", clientId)
	data.Set("device_code", deviceCode)
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

	req, err := http.NewRequest("POST", GITHUB_ACCESSTOKEN_URL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	var result AccessTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &result, nil
}

func exchangeCodeForAccessToken(client *http.Client, clientID, clientSecret, code,
	codeVerifier string) (*AccessTokenResponse, error) {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("code", code)
	data.Set("code_verifier", codeVerifier)

	req, err := http.NewRequest("POST", GITHUB_ACCESSTOKEN_URL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create access token request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("perform access token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("access token request returned status %d", resp.StatusCode)
	}

	var tokenResp AccessTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decode access token response: %w", err)
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("access token error: %s", tokenResp.Error)
	}

	return &tokenResp, nil
}

func getPublicKeys(client *http.Client, username string, accessToken string) ([]string, error) {
	keysURL := fmt.Sprintf(GITHUB_KEYS_URL, username)
	keysResource, _, err := MakeRequest(client, "GET", keysURL, accessToken, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get user keys: %w", err)
	}

	keysList, ok := keysResource.([]any)
	if !ok {
		return nil, fmt.Errorf("unexpected keys response format")
	}

	var keys []string
	for _, key := range keysList {
		keyMap, ok := key.(map[string]any)
		if ok {
			if k, exists := keyMap["key"].(string); exists && k != "" {
				keys = append(keys, k)
			}
		}
	}

	return keys, nil
}

// githubGetRepo fetches repository information from GitHub API
func GetRepo(owner, repo, token string) (*GitHubRepo, error) {
	url := fmt.Sprintf(GITHUB_REPO_URL, owner, repo)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var repoData GitHubRepo
		if err := json.NewDecoder(resp.Body).Decode(&repoData); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		return &repoData, nil
	case http.StatusNotFound:
		return nil, fmt.Errorf("repository '%s/%s' not found", owner, repo)
	default:
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error: %d %s", resp.StatusCode, string(body))
	}
}

// GetFile fetches file content from GitHub repository
func GetFile(owner, repo, token, file string, ref string) ([]byte, error) {
	baseURL := fmt.Sprintf(GITHUB_FILE_CONTENT_URL, owner, repo, file)

	if ref != "" {
		baseURL += fmt.Sprintf("?ref=%s", url.QueryEscape(ref))
	}

	req, err := http.NewRequest("GET", baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var fileContent FileContent
		if err := json.NewDecoder(resp.Body).Decode(&fileContent); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}

		contentBytes, err := base64.StdEncoding.DecodeString(fileContent.Content)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 content: %w", err)
		}

		return contentBytes, nil
	case http.StatusNotFound:
		return nil, fmt.Errorf("repository %s/%s does not exist or %s file not found", owner, repo, file)
	case http.StatusForbidden:
		return nil, fmt.Errorf("access denied to the repository %s/%s", owner, repo)
	case http.StatusBadRequest:
		return nil, fmt.Errorf("cannot access repository %s/%s or %s file", owner, repo, file)
	default:
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error.\ncode=%d, response=%s", resp.StatusCode, string(body))
	}
}

// GetRef fetches a Git ref (e.g. heads/main, tags/v1.0.0) from GitHub.
func GetRef(owner, repo, ref, token string) (*GitRef, error) {
	url := fmt.Sprintf(GITHUB_REF_URL, owner, repo, ref)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var refData GitRef
		if err := json.NewDecoder(resp.Body).Decode(&refData); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		return &refData, nil
	case http.StatusNotFound:
		return nil, fmt.Errorf("ref '%s' not found in repository '%s/%s'", ref, owner, repo)
	default:
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error: %d %s", resp.StatusCode, string(body))
	}
}

// getRepoRefFromIssue uses GitHub GraphQL API to resolve the first linked branch ref for an issue,
// returning the first branch that matches the repository owner/name.
func getRepoRefFromIssue(owner, repo string, issueNumber int, token string) (string, error) {
	reqBody := map[string]any{
		"query": `query($owner:String!, $repo:String!, $number:Int!) {
  repository(owner:$owner, name:$repo) {
    issue(number:$number) {
      linkedBranches(first: 50) {
        nodes {
          ref {
            name
            repository {
              name
              owner { login }
            }
          }
        }
      }
    }
  }
}`,
		"variables": map[string]any{
			"owner":  owner,
			"repo":   repo,
			"number": issueNumber,
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal graphql request: %w", err)
	}

	req, err := http.NewRequest("POST", githubGraphQLEndpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("create graphql request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", IDENTITY_USERAGENT)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("execute graphql request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("graphql request failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	var gqlResp struct {
		Data struct {
			Repository struct {
				Issue struct {
					LinkedBranches struct {
						Nodes []struct {
							Ref struct {
								Name       string `json:"name"`
								Repository struct {
									Name  string `json:"name"`
									Owner struct {
										Login string `json:"login"`
									} `json:"owner"`
								} `json:"repository"`
							} `json:"ref"`
						} `json:"nodes"`
					} `json:"linkedBranches"`
				} `json:"issue"`
			} `json:"repository"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&gqlResp); err != nil {
		return "", fmt.Errorf("decode graphql response: %w", err)
	}

	if len(gqlResp.Errors) > 0 {
		return "", fmt.Errorf("graphql error: %s", gqlResp.Errors[0].Message)
	}

	nodes := gqlResp.Data.Repository.Issue.LinkedBranches.Nodes
	if len(nodes) == 0 {
		return "", fmt.Errorf("no linked branches found for issue #%d", issueNumber)
	}

	for _, n := range nodes {
		ref := n.Ref
		if ref.Name == "" {
			continue
		}
		if strings.EqualFold(ref.Repository.Owner.Login, owner) &&
			strings.EqualFold(ref.Repository.Name, repo) {
			return ref.Name, nil
		}
	}

	return "", fmt.Errorf("no valid linked branch ref name found for issue #%d", issueNumber)
}
