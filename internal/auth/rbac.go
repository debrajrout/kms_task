// internal/auth/rbac.go
package auth

import (
	"errors"
)

// Role defines the type for user roles.
type Role string

// Define user roles
const (
	RoleAdmin   Role = "ADMIN"
	RoleService Role = "SERVICE"
	RoleAuditor Role = "AUDITOR"
)

// Action defines the type for actions that can be authorized.
type Action string

// Define actions
const (
	ActionGenerateDataKey Action = "GENERATE_DATA_KEY"
	ActionEncrypt         Action = "ENCRYPT"
	ActionDecrypt         Action = "DECRYPT"
	ActionRotateMasterKey Action = "ROTATE_MASTER_KEY"
)

// Identity represents a user's identity and role.
// Ensure that it contains all necessary fields used in middleware and handlers.
type Identity struct {
	Name string
	Role Role
	// Uncomment the following line if you need to include FirebaseUID
	// FirebaseUID string
}

// IsAuthorized checks if the user's role allows performing the specified action.
func IsAuthorized(id Identity, action Action) error {
	switch id.Role {
	case RoleAdmin:
		// Admins can perform any action
		return nil
	case RoleService:
		// Services can generate data keys, encrypt, and decrypt
		switch action {
		case ActionGenerateDataKey, ActionEncrypt, ActionDecrypt:
			return nil
		default:
			return errors.New("action not authorized for SERVICE role")
		}
	case RoleAuditor:
		// Auditors have read-only access (if applicable)
		// Adjust based on your requirements
		return errors.New("action not authorized for AUDITOR role")
	default:
		return errors.New("unknown role")
	}
}
