package auth

import "errors"

// Role defines user roles
type Role string

const (
	RoleAdmin   Role = "ADMIN"
	RoleService Role = "SERVICE"
	RoleAuditor Role = "AUDITOR"
)

// Action defines authorized actions
type Action string

const (
	ActionGenerateDataKey Action = "GENERATE_DATA_KEY"
	ActionEncrypt         Action = "ENCRYPT"
	ActionDecrypt         Action = "DECRYPT"
	ActionRotateMasterKey Action = "ROTATE_MASTER_KEY"
)

// Identity is placed in request context
type Identity struct {
	Name string
	Role Role
}

// IsAuthorized checks if the user's role can perform the specified action.
func IsAuthorized(id Identity, action Action) error {
	switch id.Role {
	case RoleAdmin:
		// Admin can do all
		return nil
	case RoleService:
		// Service can generate data keys, encrypt, decrypt
		switch action {
		case ActionGenerateDataKey, ActionEncrypt, ActionDecrypt:
			return nil
		default:
			return errors.New("action not authorized for SERVICE role")
		}
	case RoleAuditor:
		// Auditors can do (??) - typically read-only. Adjust as needed.
		return errors.New("action not authorized for AUDITOR role")
	default:
		return errors.New("unknown role")
	}
}
