package maestro

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"

	"github.com/openshift/rosa-regional-frontend-api/pkg/config"
)

const (
	consumersPath = "/api/maestro/v1/consumers"
)

// Client provides access to the Maestro API
type Client struct {
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
}

// NewClient creates a new Maestro client
func NewClient(cfg config.MaestroConfig, logger *slog.Logger) *Client {
	return &Client{
		baseURL: cfg.BaseURL,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		logger: logger,
	}
}

// CreateConsumer creates a new consumer in Maestro
func (c *Client) CreateConsumer(ctx context.Context, req *ConsumerCreateRequest) (*Consumer, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+consumersPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	c.logger.Debug("creating consumer in Maestro", "name", req.Name)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		var apiErr Error
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Reason != "" {
			return nil, &apiErr
		}
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(respBody))
	}

	var consumer Consumer
	if err := json.Unmarshal(respBody, &consumer); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	c.logger.Debug("consumer created", "id", consumer.ID, "name", consumer.Name)

	return &consumer, nil
}

// ListConsumers lists consumers from Maestro with pagination
func (c *Client) ListConsumers(ctx context.Context, page, size int) (*ConsumerList, error) {
	u, err := url.Parse(c.baseURL + consumersPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	q := u.Query()
	if page > 0 {
		q.Set("page", strconv.Itoa(page))
	}
	if size > 0 {
		q.Set("size", strconv.Itoa(size))
	}
	u.RawQuery = q.Encode()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.logger.Debug("listing consumers from Maestro", "page", page, "size", size)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var apiErr Error
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Reason != "" {
			return nil, &apiErr
		}
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(respBody))
	}

	var list ConsumerList
	if err := json.Unmarshal(respBody, &list); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	c.logger.Debug("consumers listed", "total", list.Total)

	return &list, nil
}

// GetConsumer retrieves a consumer by ID from Maestro
func (c *Client) GetConsumer(ctx context.Context, id string) (*Consumer, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+consumersPath+"/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.logger.Debug("getting consumer from Maestro", "id", id)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		var apiErr Error
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Reason != "" {
			return nil, &apiErr
		}
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(respBody))
	}

	var consumer Consumer
	if err := json.Unmarshal(respBody, &consumer); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	c.logger.Debug("consumer retrieved", "id", consumer.ID, "name", consumer.Name)

	return &consumer, nil
}
