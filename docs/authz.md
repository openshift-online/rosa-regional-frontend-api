# ROSA Authorization Service

This document describes the Cedar/AVP-based authorization service for the ROSA Regional Frontend API.

## Overview

The authorization service provides fine-grained access control for ROSA operations using:

- **Amazon Verified Permissions (AVP)** for policy evaluation
- **Cedar** as the policy language
- **DynamoDB** for storing accounts, admins, groups, policies, and attachments
- **IAM-like v0 policy format** that gets translated to Cedar

## Architecture

```
Request
    ↓
Identity Middleware (extract accountId, callerArn from headers)
    ↓
Privileged Check
    ├── Is accountId in configmap? → ALLOW (bypass all)
    ├── Is accountId in DB with privileged=true? → ALLOW (bypass all)
    └── Neither → continue
    ↓
Account Provisioned Check
    ├── Is accountId in DB with privileged=false? → continue
    └── Not in DB → 403 "Account not provisioned"
    ↓
Admin Check
    ├── Is callerArn an admin for this account? → ALLOW
    └── Not admin → continue
    ↓
AVP Authorization
    ├── Get user's group memberships from DynamoDB
    ├── Build AVP IsAuthorized request
    ├── Call AVP with policyStoreId from DB
    └── Return ALLOW/DENY based on AVP decision
    ↓
Handler
```

## Package Structure

```
pkg/authz/
├── authz.go              # Main Authorizer interface and implementation
├── config.go             # Configuration types
├── client/
│   ├── interface.go      # Client interfaces (for mocking)
│   ├── dynamodb.go       # DynamoDB client wrapper
│   └── avp.go            # AWS Verified Permissions client wrapper
├── policy/
│   ├── types.go          # V0Policy, Statement types
│   ├── translator.go     # IAM v0 format -> Cedar translator
│   └── validation.go     # Policy validation
├── store/
│   ├── accounts.go       # Account operations
│   ├── admins.go         # Admin CRUD
│   ├── groups.go         # Group CRUD
│   ├── members.go        # Group membership CRUD
│   ├── policies.go       # Policy template CRUD
│   └── attachments.go    # Policy attachment CRUD
├── privileged/
│   └── privileged.go     # Privileged account check (configmap + DB)
└── schema/
    ├── schema.go         # Cedar schema embedding
    ├── rosa.cedarschema  # Human-readable Cedar schema
    └── rosa.cedarschema.json # JSON schema for AVP
```

## Configuration

The authorization service is configured via the `authz.Config` struct:

```go
type Config struct {
    AWSRegion              string // AWS region for AVP and DynamoDB
    PrivilegedAccountsFile string // Path to configmap with privileged accounts
    AccountsTableName      string // DynamoDB table: rosa-authz-accounts
    AdminsTableName        string // DynamoDB table: rosa-authz-admins
    GroupsTableName        string // DynamoDB table: rosa-authz-groups
    MembersTableName       string // DynamoDB table: rosa-authz-group-members
    PoliciesTableName      string // DynamoDB table: rosa-authz-policies
    AttachmentsTableName   string // DynamoDB table: rosa-authz-attachments
    Enabled                bool   // Enable Cedar/AVP authorization
}
```

### Environment Configuration

Set `cfg.Authz.Enabled = true` to enable Cedar/AVP authorization. When disabled, the API falls back to the legacy allowlist behavior.

## Privileged Accounts

Privileged accounts bypass all authorization checks. They are defined in two sources:

### 1. Configmap File (Bootstrap)

Located at `/etc/rosa/privileged-accounts.txt`:

```
111122223333
444455556666
```

One AWS account ID per line. Comments (lines starting with `#`) are ignored.

### 2. Database

Accounts in `rosa-authz-accounts` table with `privileged: true`.

### Privileged Account Behavior

- No policy store is created (policyStoreId is null)
- All authorization checks are bypassed
- Can call the account management APIs

## API Endpoints

### Account Management (Privileged Only)

| Method | Path                    | Description                              |
| ------ | ----------------------- | ---------------------------------------- |
| POST   | `/api/v0/accounts`      | Enable an account (creates policy store) |
| GET    | `/api/v0/accounts`      | List all enabled accounts                |
| GET    | `/api/v0/accounts/{id}` | Get account details                      |
| DELETE | `/api/v0/accounts/{id}` | Disable account (deletes policy store)   |

**Enable Account Request:**

```json
{
  "accountId": "777788889999",
  "privileged": false
}
```

### Policy Management

| Method | Path                          | Description            |
| ------ | ----------------------------- | ---------------------- |
| POST   | `/api/v0/authz/policies`      | Create policy template |
| GET    | `/api/v0/authz/policies`      | List policies          |
| GET    | `/api/v0/authz/policies/{id}` | Get policy             |
| PUT    | `/api/v0/authz/policies/{id}` | Update policy          |
| DELETE | `/api/v0/authz/policies/{id}` | Delete policy          |

### Group Management

| Method | Path                                | Description          |
| ------ | ----------------------------------- | -------------------- |
| POST   | `/api/v0/authz/groups`              | Create group         |
| GET    | `/api/v0/authz/groups`              | List groups          |
| GET    | `/api/v0/authz/groups/{id}`         | Get group            |
| DELETE | `/api/v0/authz/groups/{id}`         | Delete group         |
| PUT    | `/api/v0/authz/groups/{id}/members` | Update group members |
| GET    | `/api/v0/authz/groups/{id}/members` | List group members   |

### Attachment Management

| Method | Path                             | Description                 |
| ------ | -------------------------------- | --------------------------- |
| POST   | `/api/v0/authz/attachments`      | Attach policy to user/group |
| GET    | `/api/v0/authz/attachments`      | List attachments            |
| DELETE | `/api/v0/authz/attachments/{id}` | Detach policy               |

### Admin Management

| Method | Path                         | Description  |
| ------ | ---------------------------- | ------------ |
| POST   | `/api/v0/authz/admins`       | Add admin    |
| GET    | `/api/v0/authz/admins`       | List admins  |
| DELETE | `/api/v0/authz/admins/{arn}` | Remove admin |

## Policy Format (v0)

Policies use an IAM-like JSON format:

```json
{
  "version": "v0",
  "statements": [
    {
      "sid": "AllowDevClusters",
      "effect": "Allow",
      "actions": ["rosa:CreateCluster", "rosa:DeleteCluster"],
      "resources": ["*"],
      "conditions": {
        "StringEquals": {
          "rosa:ResourceTag/Environment": "development"
        }
      }
    }
  ]
}
```

**Note:** No `principals` field - policies are templates. Principals are specified when attaching.

### Attachment Workflow

1. Create a policy template (no principal)
2. Attach the policy to a user or group
3. The system translates the policy to Cedar with the principal clause and creates it in AVP

## Supported Condition Keys

| Key                          | Description                            |
| ---------------------------- | -------------------------------------- |
| `rosa:ResourceTag/${TagKey}` | Tags on existing resources             |
| `rosa:RequestTag/${TagKey}`  | Tags in create request                 |
| `rosa:TagKeys`               | List of tag keys in request            |
| `aws:PrincipalArn`           | Caller's ARN (from headers)            |
| `aws:PrincipalAccount`       | Caller's account ID                    |
| `rosa:principalArn`          | Principal ARN in access entry requests |

## Condition Operators

The policy translator supports a subset of AWS IAM condition operators. The following tables show which operators are implemented and which are not yet available.

### Implemented Operators

| Operator                       | Category  | Description                                  | Cedar Translation                         |
| ------------------------------ | --------- | -------------------------------------------- | ----------------------------------------- |
| `StringEquals`                 | String    | Exact case-sensitive string match            | `key == "value"`                          |
| `StringNotEquals`              | String    | Negated exact string match                   | `key != "value"`                          |
| `StringLike`                   | String    | Case-sensitive wildcard match (`*`, `?`)     | `key like "pattern"`                      |
| `StringNotLike`                | String    | Negated wildcard match                       | `!(key like "pattern")`                   |
| `ArnEquals`                    | ARN       | Exact ARN match                              | `key == "arn"`                            |
| `ArnNotEquals`                 | ARN       | Negated exact ARN match                      | `key != "arn"`                            |
| `ArnLike`                      | ARN       | Wildcard ARN match                           | `key like "arn-pattern"`                  |
| `ArnNotLike`                   | ARN       | Negated wildcard ARN match                   | `!(key like "arn-pattern")`               |
| `Bool`                         | Boolean   | Boolean value check                          | `key == true/false`                       |
| `NumericEquals`                | Numeric   | Exact numeric comparison                     | `key == 100`                              |
| `NumericNotEquals`             | Numeric   | Negated numeric comparison                   | `key != 100`                              |
| `NumericLessThan`              | Numeric   | Less than comparison                         | `key < 100`                               |
| `NumericLessThanEquals`        | Numeric   | Less than or equal                           | `key <= 100`                              |
| `NumericGreaterThan`           | Numeric   | Greater than comparison                      | `key > 100`                               |
| `NumericGreaterThanEquals`     | Numeric   | Greater than or equal                        | `key >= 100`                              |
| `DateEquals`                   | Date      | Exact date comparison                        | `datetime(key) == datetime("...")`        |
| `DateNotEquals`                | Date      | Negated date comparison                      | `datetime(key) != datetime("...")`        |
| `DateLessThan`                 | Date      | Date before comparison                       | `datetime(key) < datetime("...")`         |
| `DateLessThanEquals`           | Date      | Date on or before                            | `datetime(key) <= datetime("...")`        |
| `DateGreaterThan`              | Date      | Date after comparison                        | `datetime(key) > datetime("...")`         |
| `DateGreaterThanEquals`        | Date      | Date on or after                             | `datetime(key) >= datetime("...")`        |
| `IpAddress`                    | IP        | IP address or CIDR match                     | `ip(key).isInRange(ip("192.168.0.0/16"))` |
| `NotIpAddress`                 | IP        | Negated IP address match                     | `!ip(key).isInRange(ip("..."))`           |
| `BinaryEquals`                 | Binary    | Base64 binary comparison                     | `key == "base64value"`                    |
| `Null`                         | Existence | Check if key exists                          | `has key` / `!has key`                    |
| `ForAllValues:StringEquals`    | Set       | All values in request must be in allowed set | `key.containsAll([...])`                  |
| `ForAnyValue:StringEquals`     | Set       | At least one value in request must match     | `key.containsAny([...])`                  |
| `ForAllValues:StringNotEquals` | Set       | All values must not be in specified set      | `!key.containsAny([...])`                 |
| `ForAnyValue:StringNotEquals`  | Set       | Any value must not be in specified set       | `!key.containsAll([...])`                 |
| `ForAllValues:StringLike`      | Set       | All values match at least one pattern        | `(key like "p1" \|\| key like "p2")`      |
| `ForAnyValue:StringLike`       | Set       | Any value matches at least one pattern       | `(key like "p1" \|\| key like "p2")`      |
| `...IfExists` suffix           | Modifier  | Evaluate only if key exists                  | `(!has key \|\| (condition))`             |

### Wildcard Patterns

The `StringLike` and `ArnLike` operators support wildcards:

- `*` matches any sequence of characters
- `?` matches any single character (converted to `*` in Cedar)

**Example:**

```json
{
  "ArnLike": {
    "aws:PrincipalArn": "arn:aws:iam::*:role/Admin*"
  }
}
```

### Not Yet Implemented Operators

The following AWS IAM operators cannot be implemented in Cedar without context preprocessing:

| Operator                    | Category | Description                    | Limitation                                                                                                                         |
| --------------------------- | -------- | ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| `StringEqualsIgnoreCase`    | String   | Case-insensitive exact match   | No native support. Cedar lacks `.toLowerCase()`. Would require normalizing values before they enter the policy evaluation context. |
| `StringNotEqualsIgnoreCase` | String   | Negated case-insensitive match | Same limitation as above.                                                                                                          |

## ROSA Actions Reference

### Cluster Operations

- `rosa:CreateCluster`, `rosa:DeleteCluster`, `rosa:DescribeCluster`, `rosa:ListClusters`
- `rosa:UpdateCluster`, `rosa:UpdateClusterConfig`, `rosa:UpdateClusterVersion`

### NodePool Operations

- `rosa:CreateNodePool`, `rosa:DeleteNodePool`, `rosa:DescribeNodePool`, `rosa:ListNodePools`
- `rosa:UpdateNodePool`, `rosa:ScaleNodePool`

### Access Entry Operations

- `rosa:CreateAccessEntry`, `rosa:DeleteAccessEntry`, `rosa:DescribeAccessEntry`
- `rosa:ListAccessEntries`, `rosa:UpdateAccessEntry`

### Tagging Operations

- `rosa:TagResource`, `rosa:UntagResource`, `rosa:ListTagsForResource`

### Other

- `rosa:ListAccessPolicies`

## DynamoDB Tables

### rosa-authz-accounts

| Attribute       | Type    | Key | Description                              |
| --------------- | ------- | --- | ---------------------------------------- |
| `accountId`     | String  | PK  | AWS account ID                           |
| `policyStoreId` | String  |     | AVP policy store ID (null if privileged) |
| `privileged`    | Boolean |     | If true, bypasses Cedar                  |
| `createdAt`     | String  |     | ISO8601 timestamp                        |
| `createdBy`     | String  |     | Who enabled this account                 |

### rosa-authz-admins

| Attribute      | Type   | Key | Description          |
| -------------- | ------ | --- | -------------------- |
| `accountId`    | String | PK  | AWS account ID       |
| `principalArn` | String | SK  | Admin's ARN          |
| `createdAt`    | String |     | ISO8601              |
| `createdBy`    | String |     | Who added this admin |

### rosa-authz-groups

| Attribute     | Type   | Key | Description    |
| ------------- | ------ | --- | -------------- |
| `accountId`   | String | PK  | AWS account ID |
| `groupId`     | String | SK  | UUID           |
| `name`        | String |     | Group name     |
| `description` | String |     | Optional       |
| `createdAt`   | String |     | ISO8601        |

### rosa-authz-group-members

| Attribute           | Type   | Key | Description        |
| ------------------- | ------ | --- | ------------------ |
| `accountId`         | String | PK  | AWS account ID     |
| `groupId#memberArn` | String | SK  | Composite sort key |
| `groupId`           | String |     | For querying       |
| `memberArn`         | String |     | Member's ARN       |
| `addedAt`           | String |     | ISO8601            |

**GSI: member-groups-index** (PK: `accountId#memberArn`, SK: `groupId`)

### rosa-authz-policies

| Attribute     | Type   | Key | Description                |
| ------------- | ------ | --- | -------------------------- |
| `accountId`   | String | PK  | AWS account ID             |
| `policyId`    | String | SK  | UUID                       |
| `name`        | String |     | Policy name                |
| `description` | String |     | Optional                   |
| `v0Policy`    | String |     | JSON of v0 policy template |
| `createdAt`   | String |     | ISO8601                    |

### rosa-authz-attachments

| Attribute      | Type   | Key | Description                    |
| -------------- | ------ | --- | ------------------------------ |
| `accountId`    | String | PK  | AWS account ID                 |
| `attachmentId` | String | SK  | UUID                           |
| `policyId`     | String |     | References rosa-authz-policies |
| `targetType`   | String |     | `user` or `group`              |
| `targetId`     | String |     | ARN (user) or groupId (group)  |
| `avpPolicyId`  | String |     | The actual policy ID in AVP    |
| `createdAt`    | String |     | ISO8601                        |

**GSI: target-index** (PK: `accountId#targetType#targetId`, SK: `policyId`)
**GSI: policy-index** (PK: `accountId#policyId`, SK: `attachmentId`)

## Test Cases

Policy test cases are located in `pkg/authz/testdata/policies/`. These JSON files define policies and expected authorization outcomes for testing the policy translator and documenting supported policy patterns.

### Directory Structure

```
pkg/authz/testdata/policies/
├── 01-basic-access/              # Basic read/list/describe operations
├── 02-cluster-management/        # Create, update, delete cluster operations
├── 03-nodepool-management/       # NodePool lifecycle operations
├── 04-access-entry-management/   # Access entry and policy association
├── 05-tag-based-access/          # ABAC with resource tags
├── 06-deny-policies/             # Explicit deny scenarios
├── 07-condition-keys/            # Condition key usage examples
└── 08-complex-scenarios/         # Multi-statement, combined allow/deny
```

### Test Case Format

```json
{
  "id": "unique-test-id",
  "name": "Descriptive name",
  "description": "What this policy accomplishes",
  "policy": {
    "Version": "2012-10-17",
    "Statement": [...]
  },
  "testCases": [
    {
      "description": "Test scenario",
      "request": {
        "action": "rosa:ActionName",
        "resource": "arn:aws:rosa:...",
        "resourceTags": {"key": "value"}
      },
      "expectedResult": "ALLOW | DENY | NOT_EVALUATED"
    }
  ]
}
```

## Running Tests

```bash
# Run all authz package tests
make test-authz

# Run specific package tests
make test-unit PKG=./pkg/authz/policy/...

# Run all tests
make test
```

## Example: Setting Up Authorization

```bash
# 1. Enable an account (as privileged account)
curl -X POST /api/v0/accounts \
  -H "X-Amz-Account-Id: 111122223333" \
  -d '{"accountId": "777788889999", "privileged": false}'

# 2. Add an admin for the account
curl -X POST /api/v0/authz/admins \
  -H "X-Amz-Account-Id: 777788889999" \
  -d '{"principalArn": "arn:aws:iam::777788889999:user/admin"}'

# 3. Create a policy template
curl -X POST /api/v0/authz/policies \
  -H "X-Amz-Account-Id: 777788889999" \
  -d '{
    "name": "DevClusterAccess",
    "description": "Full access to development clusters",
    "policy": {
      "version": "v0",
      "statements": [{
        "effect": "Allow",
        "actions": ["rosa:*"],
        "resources": ["*"],
        "conditions": {
          "StringEquals": {"rosa:ResourceTag/Environment": "development"}
        }
      }]
    }
  }'

# 4. Create a group
curl -X POST /api/v0/authz/groups \
  -H "X-Amz-Account-Id: 777788889999" \
  -d '{"name": "developers", "description": "Developer team"}'

# 5. Add members to the group
curl -X PUT /api/v0/authz/groups/{groupId}/members \
  -H "X-Amz-Account-Id: 777788889999" \
  -d '{"add": ["arn:aws:iam::777788889999:user/alice"]}'

# 6. Attach the policy to the group
curl -X POST /api/v0/authz/attachments \
  -H "X-Amz-Account-Id: 777788889999" \
  -d '{
    "policyId": "{policyId}",
    "targetType": "group",
    "targetId": "{groupId}"
  }'
```
