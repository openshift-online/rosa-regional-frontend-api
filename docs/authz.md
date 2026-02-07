# ROSA Authorization Service

This document describes the Cedar/AVP-based authorization service for the ROSA Regional Frontend API.

## Overview

The authorization service provides fine-grained access control for ROSA operations using:

- **Amazon Verified Permissions (AVP)** for policy evaluation
- **Cedar** as the policy language (policies are written directly in Cedar)
- **DynamoDB** for storing accounts, admins, and groups

## Architecture

```
Request
    |
Identity Middleware (extract accountId, callerArn from headers)
    |
Privileged Check
    |-- Is accountId in DB with privileged=true? -> ALLOW (bypass all)
    +-- Not privileged -> continue
    |
Account Provisioned Check
    |-- Is accountId in DB with privileged=false? -> continue
    +-- Not in DB -> 403 "Account not provisioned"
    |
Admin Check
    |-- Is callerArn an admin for this account? -> ALLOW
    +-- Not admin -> continue
    |
AVP Authorization
    |-- Get user's group memberships from DynamoDB
    |-- Build AVP IsAuthorized request
    |-- Call AVP with policyStoreId from DB
    +-- Return ALLOW/DENY based on AVP decision
    |
Handler
```

## Policy Lifecycle

```
1. Create Policy Template
   POST /api/v0/authz/policies { name, description, policy (Cedar with ?principal) }
       |
   authz.CreatePolicy()
       |-- Get account's policyStoreId from DynamoDB
       |-- Encode name+description as JSON in AVP Description field
       |-- avpClient.CreatePolicyTemplate(policyStoreId, statement, description)
       |       |
       |       |-- [Production] AVP stores template with ?principal slot
       |       +-- [Testing]    MockAVPClient stores template in memory
       |
       +-- Return policyId (= AVP PolicyTemplateId)

2. Attach Policy to Group/User
   POST /api/v0/authz/attachments { policyId, targetType, targetId }
       |
   authz.AttachPolicy()
       |-- Get account's policyStoreId from DynamoDB
       |-- Build principal entity (ROSA::Group or ROSA::Principal)
       |-- avpClient.CreatePolicy(TemplateLinked { templateId, principal })
       |       |
       |       |-- [Production] AVP creates template-linked policy
       |       |                ?principal bound to concrete entity
       |       |
       |       +-- [Testing]    MockAVPClient resolves ?principal client-side
       |                        Stores resolved static Cedar text in memory
       |
       +-- Return attachment (attachmentId = AVP policy ID)

3. Authorization Check
   Request with X-Amz-Account-Id, X-Amz-Caller-Arn headers
       |
   authz.Authorize()
       |-- Get group memberships from DynamoDB
       |-- Build IsAuthorized request (principal, action, resource, groups, tags)
       |-- avpClient.IsAuthorized(policyStoreId, ...)
       |       |
       |       |-- [Production] AVP evaluates all policies (including template-linked)
       |       |
       |       +-- [Testing]    MockAVPClient syncs resolved policies to cedar-agent
       |                        cedar-agent evaluates Cedar policies locally
       |
       +-- Return ALLOW / DENY

4. Update Policy Template
   PUT /api/v0/authz/policies/{id} { name, description, policy }
       |
   authz.UpdatePolicy()
       |-- avpClient.UpdatePolicyTemplate(templateId, newStatement)
       |       |
       |       |-- [Production] AVP updates template
       |       |                Auto-propagates to all template-linked policies
       |       |
       |       +-- [Testing]    MockAVPClient updates template in memory
       |                        Re-resolves all linked policies, syncs to cedar-agent
       |
       +-- Return updated policy
```

## Configuration

The authorization service is configured via the `authz.Config` struct:

```go
type Config struct {
    AWSRegion         string // AWS region for AVP and DynamoDB
    AccountsTableName string // DynamoDB table: rosa-authz-accounts
    AdminsTableName   string // DynamoDB table: rosa-authz-admins
    GroupsTableName   string // DynamoDB table: rosa-authz-groups
    MembersTableName  string // DynamoDB table: rosa-authz-group-members
    Enabled           bool   // Enable Cedar/AVP authorization
}
```

## Privileged Accounts

Privileged accounts bypass all authorization checks. They are stored in the `rosa-authz-accounts` DynamoDB table with `privileged: true`.

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

| Method | Path                          | Description   |
| ------ | ----------------------------- | ------------- |
| POST   | `/api/v0/authz/policies`      | Create policy |
| GET    | `/api/v0/authz/policies`      | List policies |
| GET    | `/api/v0/authz/policies/{id}` | Get policy    |
| PUT    | `/api/v0/authz/policies/{id}` | Update policy |
| DELETE | `/api/v0/authz/policies/{id}` | Delete policy |

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

## Policy Format

Policies are written directly in [Cedar](https://docs.cedarpolicy.com/). The `?principal` placeholder is used as a template variable — when a policy is attached to a user or group, the system resolves `?principal` to the concrete principal entity.

### Example: Allow development cluster access

```cedar
permit(
  ?principal,
  action in [ROSA::Action::"CreateCluster", ROSA::Action::"DeleteCluster",
             ROSA::Action::"DescribeCluster", ROSA::Action::"UpdateCluster"],
  resource
)
when { resource.tags["Environment"] == "development" };
```

### Example: Deny production deletions

```cedar
forbid(
  ?principal,
  action == ROSA::Action::"DeleteCluster",
  resource
)
when { resource.tags["Environment"] == "production" };
```

### Example: Require MFA for destructive operations

```cedar
forbid(
  ?principal,
  action in [ROSA::Action::"DeleteCluster", ROSA::Action::"DeleteNodePool"],
  resource
)
when { context.mfaPresent == "false" };
```

### Attachment Workflow

1. Create a Cedar policy template in AVP (uses `?principal` placeholder)
2. Attach the policy to a user or group
3. AVP creates a template-linked policy binding the concrete principal

### Create Policy Request

```json
{
  "name": "DevClusterAccess",
  "description": "Full access to development clusters",
  "policy": "permit(\n  ?principal,\n  action,\n  resource\n)\nwhen { resource.tags[\"Environment\"] == \"development\" };"
}
```

## ROSA Actions Reference

All actions use the `ROSA::Action` entity type in Cedar policies.

### Cluster Operations

- `CreateCluster`, `DeleteCluster`, `DescribeCluster`, `ListClusters`
- `UpdateCluster`, `UpdateClusterConfig`, `UpdateClusterVersion`

### NodePool Operations

- `CreateNodePool`, `DeleteNodePool`, `DescribeNodePool`, `ListNodePools`
- `UpdateNodePool`, `ScaleNodePool`

### Access Entry Operations

- `CreateAccessEntry`, `DeleteAccessEntry`, `DescribeAccessEntry`
- `ListAccessEntries`, `UpdateAccessEntry`

### Tagging Operations

- `TagResource`, `UntagResource`, `ListTagsForResource`

### Other

- `ListAccessPolicies`

## Cedar Schema

The ROSA Cedar schema defines the following entity types:

- **`ROSA::Principal`** — Users identified by ARN
- **`ROSA::Group`** — Groups that principals can be members of (parents of Principal)
- **`ROSA::Resource`** — Base resource type with `tags: Map<String, String>`
- **`ROSA::Cluster`** — Inherits from Resource
- **`ROSA::NodePool`** — Inherits from Resource
- **`ROSA::AccessEntry`** — Inherits from Resource

The full schema is at `pkg/authz/schema/rosa.cedarschema`.

## Context Attributes

Cedar policies can reference context attributes passed with authorization requests:

| Attribute          | Type               | Description                           |
| ------------------ | ------------------ | ------------------------------------- |
| `mfaPresent`       | String             | Whether MFA was used ("true"/"false") |
| `principalArn`     | String             | Principal ARN in access entry ops     |
| `principalTags`    | Map<String,String> | Tags associated with the principal    |
| `tagKeys`          | Set<String>        | Tag keys being modified               |
| `requestTags`      | Map<String,String> | Tags in create/tag requests           |
| `accessScope`      | String             | "namespace" or "cluster"              |
| `namespaces`       | Set<String>        | Kubernetes namespaces                 |
| `kubernetesGroups` | Set<String>        | Kubernetes groups in access entries   |
| `policyArn`        | String             | Access policy ARN                     |
| `username`         | String             | Caller username                       |

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

## Test Cases

Policy test cases are located in `pkg/authz/testdata/policies/`. These JSON files define Cedar policies and expected authorization outcomes for testing.

### Directory Structure

```
pkg/authz/testdata/policies/
|-- 01-basic-access/              # Basic read/list/describe operations
|-- 02-cluster-management/        # Create, update, delete cluster operations
|-- 03-nodepool-management/       # NodePool lifecycle operations
|-- 04-access-entry-management/   # Access entry and policy association
|-- 05-tag-based-access/          # ABAC with resource tags
|-- 06-deny-policies/             # Explicit deny scenarios
|-- 07-condition-keys/            # Condition key usage examples
+-- 08-complex-scenarios/         # Multi-statement, combined allow/deny
```

### Test Case Format

Each test case is a JSON file with a companion `.cedar` file containing the Cedar policy text:

**`list-clusters.json`:**

```json
{
  "id": "unique-test-id",
  "name": "Descriptive name",
  "description": "What this policy accomplishes",
  "policyFile": "list-clusters.cedar",
  "testCases": [
    {
      "description": "Test scenario",
      "request": {
        "action": "ListClusters",
        "resource": "*",
        "resourceTags": { "Environment": "production" }
      },
      "expectedResult": "ALLOW"
    }
  ]
}
```

**`list-clusters.cedar`:**

```cedar
permit(
  ?principal,
  action == ROSA::Action::"ListClusters",
  resource
);
```

## Running Tests

```bash
# Run all authz package tests
make test-authz

# Run E2E authz tests (requires podman-compose with cedar-agent + DynamoDB Local)
make test-e2e-authz

# Run all tests
make test
````

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

# 3. Create a Cedar policy
curl -X POST /api/v0/authz/policies \
  -H "X-Amz-Account-Id: 777788889999" \
  -d '{
    "name": "DevClusterAccess",
    "description": "Full access to development clusters",
    "policy": "permit(\n  ?principal,\n  action,\n  resource\n)\nwhen { resource.tags[\"Environment\"] == \"development\" };"
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

## Further Reading

- [Cedar Language Reference](https://docs.cedarpolicy.com/)
- [Amazon Verified Permissions Documentation](https://docs.aws.amazon.com/verifiedpermissions/)
