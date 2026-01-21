package dynamodb

import "time"

// CustomerAccount represents a customer account record in DynamoDB
type CustomerAccount struct {
	AccountID  string    `dynamodbav:"account_id"`
	Privileged bool      `dynamodbav:"privileged"`
	CreatedAt  time.Time `dynamodbav:"created_at"`
	UpdatedAt  time.Time `dynamodbav:"updated_at"`
}
