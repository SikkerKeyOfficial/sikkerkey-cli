// Package client provides the HTTP client for talking to the SikkerKey API.
//
// All requests are signed with the machine's Ed25519 key.
package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/SikkerKeyOfficial/sikkerkey-cli/internal/auth"
)

// Client talks to the SikkerKey API.
type Client struct {
	baseURL string
	signer  *auth.Signer
	http    *http.Client
}

// New creates a Client with the given base URL and signer.
func New(baseURL string, signer *auth.Signer) *Client {
	// Local-dev override: SIKKERKEY_API_URL repoints the CLI at an alternate
	// endpoint (e.g. a local machine-service on :8081) without rewriting the
	// installed identity's apiUrl. Dev-only; never surfaced to customers.
	if override := strings.TrimSpace(os.Getenv("SIKKERKEY_API_URL")); override != "" {
		baseURL = override
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		signer:  signer,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// SecretResponse is the JSON body returned by GET /v1/secret/{id}.
type SecretResponse struct {
	Value string `json:"value"`
}

// ErrorResponse is the JSON body returned on errors.
type ErrorResponse struct {
	Error string `json:"error"`
}

// ApiError is an error with an HTTP status code.
type ApiError struct {
	StatusCode int
	Message    string
}

func (e *ApiError) Error() string { return e.Message }

// IsTerminalError returns true if the error indicates the agent should stop (404, 403).
func IsTerminalError(err error) bool {
	if ae, ok := err.(*ApiError); ok {
		return ae.StatusCode == 404 || ae.StatusCode == 403
	}
	return false
}

// newAPIError builds an ApiError from an HTTP status + body, preferring the
// server's JSON {error} message.
func newAPIError(code int, body []byte) *ApiError {
	msg := fmt.Sprintf("HTTP %d: %s", code, string(body))
	var errResp ErrorResponse
	if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
		msg = errResp.Error
	}
	return &ApiError{StatusCode: code, Message: msg}
}

// transportError wraps a connection-level failure (DNS, refused, TLS, timeout,
// dropped mid-read) as an ApiError with StatusCode 0 — the signal the fallback
// cache keys on to mean "the server couldn't be reached at all".
func transportError(err error) *ApiError {
	return &ApiError{StatusCode: 0, Message: fmt.Sprintf("request failed: %s", err)}
}

// unavailableStatuses are the HTTP statuses that mean no authoritative answer
// reached us from the origin, so the fallback cache may serve the request:
// 502/504 (gateway couldn't get a usable origin response), 503 (temporarily
// unavailable), 520–527 (the Cloudflare origin-error family: down / refused / timeout /
// unreachable / edge↔origin TLS failure), and 530 (edge couldn't resolve or reach
// the origin). 401/403/404/429 are authoritative answers and are deliberately
// excluded, as are 500/501 (the origin ran and errored).
var unavailableStatuses = map[int]bool{
	502: true, 503: true, 504: true,
	520: true, 521: true, 522: true, 523: true, 524: true, 525: true, 526: true, 527: true,
	530: true,
}

// IsUnavailable reports whether err means the retrieval plane couldn't give an
// authoritative answer — a transport failure (StatusCode 0) or a gateway/origin
// unreachable status (see unavailableStatuses). These, and ONLY these, may be
// satisfied from the fallback cache; a 401/403/404 is a real answer (bad auth,
// revoked access, deleted secret) and must never be masked by the cache.
func IsUnavailable(err error) bool {
	var ae *ApiError
	if errors.As(err, &ae) {
		return ae.StatusCode == 0 || unavailableStatuses[ae.StatusCode]
	}
	return false
}

// SecretListItem is one entry from the list endpoint.
type SecretListItem struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	FieldNames *string `json:"fieldNames"`
	ProjectID  *string `json:"projectId"`
}

// SecretListResponse is the JSON body from GET /v1/secrets.
type SecretListResponse struct {
	Secrets []SecretListItem `json:"secrets"`
}

// CliProject is one entry from GET /v1/cli/projects. ApplicationID /
// ApplicationName are empty for standalone projects and for responses from
// older servers that don't send them — callers must treat empty as "none".
type CliProject struct {
	ProjectID       string `json:"projectId"`
	ProjectName     string `json:"projectName"`
	ApplicationID   string `json:"applicationId"`
	ApplicationName string `json:"applicationName"`
}

// CliProjectListResponse is the JSON body from GET /v1/cli/projects.
type CliProjectListResponse struct {
	Projects []CliProject `json:"projects"`
}

// CliSecretListItem is one entry from GET /v1/cli/secrets. Adds projectName
// alongside the SDK-shape fields so display layers can group/disambiguate
// without an extra round trip per project.
type CliSecretListItem struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	FieldNames      *string `json:"fieldNames"`
	ProjectID       string  `json:"projectId"`
	ProjectName     string  `json:"projectName"`
	ApplicationID   string  `json:"applicationId"`
	ApplicationName string  `json:"applicationName"`
	// The secret's kind. Empty from a service that predates the field, which is
	// why display falls back to the fieldNames guess rather than showing nothing.
	Type string `json:"type"`
}

// CliSecretListResponse is the JSON body from GET /v1/cli/secrets.
type CliSecretListResponse struct {
	Secrets []CliSecretListItem `json:"secrets"`
}

// VerifyAccessResponse is the JSON body from POST /v1/verify-access.
type VerifyAccessResponse struct {
	Valid       bool    `json:"valid"`
	ProjectName *string `json:"projectName"`
	Error       *string `json:"error"`
}

// VerifyAccess checks that this machine can access a project.
func (c *Client) VerifyAccess(projectID string) (*VerifyAccessResponse, error) {
	path := "/v1/verify-access"
	url := c.baseURL + path

	payload := []byte(`{"projectId":` + jsonString(projectID) + `}`)

	req, err := http.NewRequest("POST", url, strings.NewReader(string(payload)))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	headers := c.signer.Headers("POST", path, payload)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var result VerifyAccessResponse
	if json.Unmarshal(body, &result) == nil && result.Error != nil && *result.Error != "" {
		if !result.Valid {
			return nil, fmt.Errorf("%s", *result.Error)
		}
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return &result, nil
}

// ListSecrets returns all secrets this machine has access to.
func (c *Client) ListSecrets() ([]SecretListItem, error) {
	path := "/v1/secrets"
	url := c.baseURL + path

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	headers := c.signer.Headers("GET", path, []byte{})
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var list SecretListResponse
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return list.Secrets, nil
}

// ListSecretsByProject returns secrets for a specific project.
func (c *Client) ListSecretsByProject(projectID string) ([]SecretListItem, error) {
	path := "/v1/secrets/list"
	url := c.baseURL + path

	reqBody, err := json.Marshal(map[string]string{"projectId": projectID})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	headers := c.signer.Headers("POST", path, reqBody)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var list SecretListResponse
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return list.Secrets, nil
}

// ListCliProjects calls GET /v1/cli/projects, returning the distinct
// projects this machine has been granted secrets in. Project name is
// resolved server-side, so no per-project verify-access round trip.
func (c *Client) ListCliProjects() ([]CliProject, error) {
	path := "/v1/cli/projects"
	url := c.baseURL + path

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	headers := c.signer.Headers("GET", path, []byte{})
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var list CliProjectListResponse
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return list.Projects, nil
}

// ListCliSecrets calls GET /v1/cli/secrets, returning every granted secret
// with project name attached. Equivalent in scope to ListSecrets() on the
// SDK surface but enriched with projectName for display.
func (c *Client) ListCliSecrets() ([]CliSecretListItem, error) {
	path := "/v1/cli/secrets"
	url := c.baseURL + path

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	headers := c.signer.Headers("GET", path, []byte{})
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var list CliSecretListResponse
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return list.Secrets, nil
}

// jsonString produces a JSON-encoded string value.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// ExportSecretEntry is one entry from the export endpoint.
type ExportSecretEntry struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Value      string  `json:"value"`
	FieldNames *string `json:"fieldNames"`
}

// ExportSecrets fetches all secret values in a single request, optionally
// scoped to a single project or to an application. projectID takes precedence;
// passing both empty exports every granted secret (unchanged behaviour).
func (c *Client) ExportSecrets(projectID, applicationID string) ([]ExportSecretEntry, error) {
	path := "/v1/secrets/export"
	url := c.baseURL + path

	var payload []byte
	if projectID != "" {
		payload, _ = json.Marshal(map[string]string{"projectId": projectID})
	} else if applicationID != "" {
		payload, _ = json.Marshal(map[string]string{"applicationId": applicationID})
	}

	var reqBody io.Reader
	if payload != nil {
		reqBody = strings.NewReader(string(payload))
	}

	req, err := http.NewRequest("POST", url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	signPayload := payload
	if signPayload == nil {
		signPayload = []byte{}
	}
	headers := c.signer.Headers("POST", path, signPayload)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, transportError(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, transportError(err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, newAPIError(resp.StatusCode, body)
	}

	var result struct {
		Secrets []ExportSecretEntry `json:"secrets"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return result.Secrets, nil
}

// GetSecret fetches a single secret by ID.
func (c *Client) GetSecret(secretID string) (string, error) {
	path := "/v1/secret/" + secretID
	url := c.baseURL + path

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	headers := c.signer.Headers("GET", path, []byte{})
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return "", transportError(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", transportError(err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", newAPIError(resp.StatusCode, body)
	}

	var secret SecretResponse
	if err := json.Unmarshal(body, &secret); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	return secret.Value, nil
}

// CertificateResponse is the JSON body returned by GET /v1/secret/{id} when the
// secret issues certificates. Fields carries whatever the certificate type needs
// alongside the certificate itself — for SSH, the username to log in as.
type CertificateResponse struct {
	Certificate     string            `json:"certificate"`
	CertificateType string            `json:"certificateType"`
	Fields          map[string]string `json:"fields"`
	ValidAfter      int64             `json:"validAfter"`
	ValidBefore     int64             `json:"validBefore"`
}

// GetCertificate signs a subject public key under the certificate secret's
// authority. It sends one subject key per certificate type — an SSH public key
// line and an X.509 SubjectPublicKeyInfo as base64 DER — and the server signs the
// one its authority calls for, naming the type in the response.
//
// The private halves never leave the caller, which is what keeps this a signing
// request rather than a credential fetch. Everything rides in headers, never a
// query string (rejected on signed routes): validitySeconds requests a SHORTER
// certificate that the server clamps to the configured maximum, so it can never be
// tampered into a longer one.
func (c *Client) GetCertificate(secretID, sshSubjectKey, x509SubjectKey string, validitySeconds int64) (*CertificateResponse, error) {
	path := "/v1/secret/" + secretID
	url := c.baseURL + path

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	headers := c.signer.Headers("GET", path, []byte{})
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("X-SikkerKey-Subject-Key", sshSubjectKey)
	req.Header.Set("X-SikkerKey-Subject-Key-X509", x509SubjectKey)
	if validitySeconds > 0 {
		req.Header.Set("X-SikkerKey-Validity", strconv.FormatInt(validitySeconds, 10))
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, transportError(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, transportError(err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, newAPIError(resp.StatusCode, body)
	}

	var out CertificateResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if out.Certificate == "" {
		// Every secret type answers this same endpoint, so what came back instead
		// says which of two different things went wrong.
		var plain SecretResponse
		if json.Unmarshal(body, &plain) == nil && plain.Value != "" {
			// A certificate secret stores "{}" as its value and never serves it;
			// the signed certificate is produced at read time. Receiving the
			// placeholder means the read never reached the certificate path, so
			// the service answering is older than certificate support.
			if strings.TrimSpace(plain.Value) == "{}" {
				return nil, fmt.Errorf("the SikkerKey service serving this secret does not support certificates yet")
			}
			return nil, fmt.Errorf("%s is not a certificate secret. Use 'sikkerkey get %s' to read it", secretID, secretID)
		}
		return nil, fmt.Errorf("server returned no certificate")
	}
	return &out, nil
}

// SyncConfig is returned by GET /v1/secret/{id}/sync-config.
type SyncConfig struct {
	ProviderType      string         `json:"providerType"`
	Connection        SyncConnection `json:"connection"`
	ManagedUsername   string         `json:"managedUsername"`
	PollIntervalSecs  int            `json:"pollIntervalSeconds"`
	PendingRotationId string         `json:"pendingRotationId,omitempty"`
	PendingValue      string         `json:"pendingValue,omitempty"`
	RotationStatus    string         `json:"rotationStatus"`
}

type SyncConnection struct {
	Host             string `json:"host"`
	Port             int    `json:"port"`
	Database         string `json:"database"`
	AdminUser        string `json:"adminUser"`
	AdminPass        string `json:"adminPass"`
	ProjectReference string `json:"projectReference,omitempty"`
}

// GetSyncConfig fetches the sync configuration for a synchronized secret.
func (c *Client) GetSyncConfig(secretID string) (*SyncConfig, error) {
	path := "/v1/secret/" + secretID + "/sync-config"
	url := c.baseURL + path

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	headers := c.signer.Headers("GET", path, []byte{})
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		msg := fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body))
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			msg = errResp.Error
		}
		return nil, &ApiError{StatusCode: resp.StatusCode, Message: msg}
	}

	var cfg SyncConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &cfg, nil
}

// SendHeartbeat reports agent health to SikkerKey.
func (c *Client) SendHeartbeat(secretID, status, errMsg string) error {
	path := "/v1/secret/" + secretID + "/agent/heartbeat"
	url := c.baseURL + path

	payload, _ := json.Marshal(map[string]string{"status": status, "error": errMsg})

	req, err := http.NewRequest("POST", url, strings.NewReader(string(payload)))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	headers := c.signer.Headers("POST", path, payload)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// ConfirmRotation tells SikkerKey the pending rotation was applied and verified.
func (c *Client) ConfirmRotation(secretID, rotationId string) error {
	path := "/v1/secret/" + secretID + "/agent/confirm-rotation"
	url := c.baseURL + path

	payload, _ := json.Marshal(map[string]string{"rotationId": rotationId})

	req, err := http.NewRequest("POST", url, strings.NewReader(string(payload)))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	headers := c.signer.Headers("POST", path, payload)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(payload)))

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// RejectRotation tells SikkerKey the pending rotation failed.
// PollChange represents a single secret's change status from the poll endpoint.
type PollChange struct {
	Status string `json:"status"`
}

// PollResponse is the response from POST /v1/secrets/poll.
type PollResponse struct {
	Changes map[string]PollChange `json:"changes"`
}

// PollSecrets checks if any of the given secrets have changed since last fetch.
func (c *Client) PollSecrets(secretIDs []string) (map[string]PollChange, error) {
	path := "/v1/secrets/poll"
	url := c.baseURL + path

	payload, _ := json.Marshal(map[string][]string{"watch": secretIDs})

	req, err := http.NewRequest("POST", url, strings.NewReader(string(payload)))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	headers := c.signer.Headers("POST", path, payload)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var pollResp PollResponse
	if err := json.Unmarshal(body, &pollResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return pollResp.Changes, nil
}

func (c *Client) RejectRotation(secretID, rotationId, errMsg string) error {
	path := "/v1/secret/" + secretID + "/agent/reject-rotation"
	url := c.baseURL + path

	payload, _ := json.Marshal(map[string]string{"rotationId": rotationId, "error": errMsg})

	req, err := http.NewRequest("POST", url, strings.NewReader(string(payload)))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	headers := c.signer.Headers("POST", path, payload)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(payload)))

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}
