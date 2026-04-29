package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ACRClient implements the Client interface for Azure Container Registry
type ACRClient struct {
	tenantID     string
	clientID     string
	clientSecret string
	registryName string
	accessToken  string
	tokenExpiry  time.Time
}

// NewACRClient creates a new ACR client
func NewACRClient(tenantID, clientID, clientSecret, registryName string) *ACRClient {
	return &ACRClient{
		tenantID:     tenantID,
		clientID:     clientID,
		clientSecret: clientSecret,
		registryName: registryName,
	}
}

// getAccessToken gets or refreshes the Azure AD access token
func (c *ACRClient) getAccessToken(ctx context.Context) (string, error) {
	// Return cached token if still valid
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry) {
		return c.accessToken, nil
	}

	// Get Azure AD token
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", c.tenantID)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)
	data.Set("scope", "https://management.azure.com/.default")

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return "", fmt.Errorf("failed to get Azure AD token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get Azure AD token: %s - %s", resp.Status, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	c.accessToken = tokenResp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second)

	return c.accessToken, nil
}

// getRegistryToken exchanges Azure AD token for ACR refresh token
func (c *ACRClient) getRegistryToken(ctx context.Context) (string, error) {
	aadToken, err := c.getAccessToken(ctx)
	if err != nil {
		return "", err
	}

	// Exchange AAD token for ACR refresh token
	exchangeURL := fmt.Sprintf("https://%s.azurecr.io/oauth2/exchange", c.registryName)

	data := url.Values{}
	data.Set("grant_type", "access_token")
	data.Set("service", fmt.Sprintf("%s.azurecr.io", c.registryName))
	data.Set("access_token", aadToken)

	resp, err := http.PostForm(exchangeURL, data)
	if err != nil {
		return "", fmt.Errorf("failed to exchange token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to exchange token: %s - %s", resp.Status, string(body))
	}

	var tokenResp struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode exchange response: %w", err)
	}

	return tokenResp.RefreshToken, nil
}

// getACRAccessToken gets an access token for a specific scope
func (c *ACRClient) getACRAccessToken(ctx context.Context, scope string) (string, error) {
	refreshToken, err := c.getRegistryToken(ctx)
	if err != nil {
		return "", err
	}

	tokenURL := fmt.Sprintf("https://%s.azurecr.io/oauth2/token", c.registryName)

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("service", fmt.Sprintf("%s.azurecr.io", c.registryName))
	data.Set("scope", scope)
	data.Set("refresh_token", refreshToken)

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return "", fmt.Errorf("failed to get ACR access token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get ACR access token: %s - %s", resp.Status, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	return tokenResp.AccessToken, nil
}

// TestConnection tests the connection to ACR
func (c *ACRClient) TestConnection(ctx context.Context) error {
	// Try to get a token which validates the credentials
	_, err := c.getACRAccessToken(ctx, "registry:catalog:*")
	if err != nil {
		return fmt.Errorf("failed to connect to ACR: %w", err)
	}
	return nil
}

// ListRepositories lists ACR repositories with pagination
func (c *ACRClient) ListRepositories(ctx context.Context, page, pageSize int) (*ListRepositoriesResponse, error) {
	token, err := c.getACRAccessToken(ctx, "registry:catalog:*")
	if err != nil {
		return nil, err
	}

	// ACR uses Docker Registry v2 API
	catalogURL := fmt.Sprintf("https://%s.azurecr.io/v2/_catalog?n=%d", c.registryName, pageSize*page)

	req, err := http.NewRequestWithContext(ctx, "GET", catalogURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list repositories: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list repositories: %s - %s", resp.Status, string(body))
	}

	var catalogResp struct {
		Repositories []string `json:"repositories"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&catalogResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Calculate which repos belong to the requested page
	startIdx := (page - 1) * pageSize
	endIdx := startIdx + pageSize
	if startIdx >= len(catalogResp.Repositories) {
		return &ListRepositoriesResponse{
			Repositories: []Repository{},
			TotalCount:   len(catalogResp.Repositories),
			Page:         page,
			PageSize:     pageSize,
		}, nil
	}
	if endIdx > len(catalogResp.Repositories) {
		endIdx = len(catalogResp.Repositories)
	}

	var repos []Repository
	for _, repoName := range catalogResp.Repositories[startIdx:endIdx] {
		repos = append(repos, Repository{
			Name:      repoName,
			FullName:  fmt.Sprintf("%s.azurecr.io/%s", c.registryName, repoName),
			IsPrivate: true, // ACR repos are always private
			PullCount: 0,    // Not available via Docker Registry API
		})
	}

	return &ListRepositoriesResponse{
		Repositories: repos,
		TotalCount:   len(catalogResp.Repositories),
		Page:         page,
		PageSize:     pageSize,
	}, nil
}

// ListTags lists tags for an ACR repository
func (c *ACRClient) ListTags(ctx context.Context, repository string, page, pageSize int) (*ListTagsResponse, error) {
	scope := fmt.Sprintf("repository:%s:pull", repository)
	token, err := c.getACRAccessToken(ctx, scope)
	if err != nil {
		return nil, err
	}

	// ACR uses Docker Registry v2 API
	tagsURL := fmt.Sprintf("https://%s.azurecr.io/v2/%s/tags/list?n=%d", c.registryName, repository, pageSize*page)

	req, err := http.NewRequestWithContext(ctx, "GET", tagsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list tags: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list tags: %s - %s", resp.Status, string(body))
	}

	var tagsResp struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tagsResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Calculate which tags belong to the requested page
	startIdx := (page - 1) * pageSize
	endIdx := startIdx + pageSize
	if startIdx >= len(tagsResp.Tags) {
		return &ListTagsResponse{
			Tags:       []Tag{},
			TotalCount: len(tagsResp.Tags),
			Page:       page,
			PageSize:   pageSize,
		}, nil
	}
	if endIdx > len(tagsResp.Tags) {
		endIdx = len(tagsResp.Tags)
	}

	var tags []Tag
	for _, tagName := range tagsResp.Tags[startIdx:endIdx] {
		// Optionally fetch manifest for size info (expensive, so skip for now)
		tags = append(tags, Tag{
			Name:      tagName,
			SizeBytes: 0, // Would need to fetch manifest
		})
	}

	return &ListTagsResponse{
		Tags:       tags,
		TotalCount: len(tagsResp.Tags),
		Page:       page,
		PageSize:   pageSize,
	}, nil
}

// GetManifest gets the manifest for a specific tag (optional, for detailed info)
func (c *ACRClient) GetManifest(ctx context.Context, repository, tag string) (string, int64, error) {
	scope := fmt.Sprintf("repository:%s:pull", repository)
	token, err := c.getACRAccessToken(ctx, scope)
	if err != nil {
		return "", 0, err
	}

	manifestURL := fmt.Sprintf("https://%s.azurecr.io/v2/%s/manifests/%s", c.registryName, repository, tag)

	req, err := http.NewRequestWithContext(ctx, "GET", manifestURL, nil)
	if err != nil {
		return "", 0, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("failed to get manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", 0, fmt.Errorf("failed to get manifest: %s - %s", resp.Status, string(body))
	}

	digest := resp.Header.Get("Docker-Content-Digest")
	contentLength := resp.ContentLength

	// Get the actual size from manifest config
	var manifest struct {
		Config struct {
			Size int64 `json:"size"`
		} `json:"config"`
		Layers []struct {
			Size int64 `json:"size"`
		} `json:"layers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err == nil {
		// Sum up all layer sizes
		for _, layer := range manifest.Layers {
			contentLength += layer.Size
		}
		contentLength += manifest.Config.Size
	}

	// Clean up digest
	if strings.HasPrefix(digest, "sha256:") {
		digest = digest[:19] // sha256: + 12 chars
	}

	return digest, contentLength, nil
}

// Provider returns the provider type
func (c *ACRClient) Provider() Provider {
	return ProviderACR
}
