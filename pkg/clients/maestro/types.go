package maestro

import "time"

// Consumer represents a Maestro consumer
type Consumer struct {
	ID        string            `json:"id,omitempty"`
	Kind      string            `json:"kind,omitempty"`
	Href      string            `json:"href,omitempty"`
	Name      string            `json:"name,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	CreatedAt *time.Time        `json:"created_at,omitempty"`
	UpdatedAt *time.Time        `json:"updated_at,omitempty"`
}

// ConsumerCreateRequest is the request body for creating a consumer
type ConsumerCreateRequest struct {
	Name   string            `json:"name,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
}

// ConsumerList is a paginated list of consumers
type ConsumerList struct {
	Kind  string     `json:"kind"`
	Page  int        `json:"page"`
	Size  int        `json:"size"`
	Total int        `json:"total"`
	Items []Consumer `json:"items"`
}

// Error represents a Maestro API error response
type Error struct {
	ID          string `json:"id,omitempty"`
	Kind        string `json:"kind,omitempty"`
	Href        string `json:"href,omitempty"`
	Code        string `json:"code,omitempty"`
	Reason      string `json:"reason,omitempty"`
	OperationID string `json:"operation_id,omitempty"`
}

func (e *Error) Error() string {
	return e.Reason
}
