package store

import (
	"time"

	"github.com/google/uuid"
)

// User is an account that can log in to the UI.
type User struct {
	ID                 uuid.UUID  `json:"id"`
	Username           string     `json:"username"`
	Email              string     `json:"email"`
	DisplayName        string     `json:"displayName"`
	PasswordHash       string     `json:"-"`
	IsAdmin            bool       `json:"isAdmin"`
	IsActive           bool       `json:"isActive"`
	MustChangePassword bool       `json:"mustChangePassword"`
	Permissions        []string   `json:"permissions"`
	LastLoginAt        *time.Time `json:"lastLoginAt,omitempty"`
	CreatedAt          time.Time  `json:"createdAt"`
	UpdatedAt          time.Time  `json:"updatedAt"`
}

// Group collects users so secrets can be shared with all of them at once.
type Group struct {
	ID          uuid.UUID     `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	CreatedBy   *uuid.UUID    `json:"createdBy,omitempty"`
	CreatedAt   time.Time     `json:"createdAt"`
	MemberCount int           `json:"memberCount"`
	SecretCount int           `json:"secretCount"`
	Members     []GroupMember `json:"members,omitempty"`
}

// GroupMember is a user's membership in a group.
type GroupMember struct {
	UserID      uuid.UUID `json:"userId"`
	Username    string    `json:"username"`
	DisplayName string    `json:"displayName"`
	Role        string    `json:"role"`
	AddedAt     time.Time `json:"addedAt"`
}

// Secret is a stored credential. The plaintext value never appears here; it is
// returned separately by the reveal endpoint.
type Secret struct {
	ID          uuid.UUID         `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Kind        string            `json:"kind"`
	Username    string            `json:"username"`
	URL         string            `json:"url"`
	OwnerID     *uuid.UUID        `json:"ownerId,omitempty"`
	OwnerName   string            `json:"ownerName,omitempty"`
	CreatedBy   *uuid.UUID        `json:"createdBy,omitempty"`
	Version     int               `json:"version"`
	CreatedAt   time.Time         `json:"createdAt"`
	UpdatedAt   time.Time         `json:"updatedAt"`
	Shares      []SecretShare     `json:"shares,omitempty"`
	UserShares  []SecretUserShare `json:"userShares,omitempty"`
	CanWrite    bool              `json:"canWrite"`
}

// SecretUserShare grants one named person access to a secret.
type SecretUserShare struct {
	UserID      uuid.UUID `json:"userId"`
	Username    string    `json:"username"`
	DisplayName string    `json:"displayName"`
	CanWrite    bool      `json:"canWrite"`
	SharedAt    time.Time `json:"sharedAt"`
}

// SecretShare grants a group access to a secret.
type SecretShare struct {
	GroupID   uuid.UUID `json:"groupId"`
	GroupName string    `json:"groupName"`
	CanWrite  bool      `json:"canWrite"`
	SharedAt  time.Time `json:"sharedAt"`
}

// SecretVersion is a superseded value kept for history and rollback.
type SecretVersion struct {
	ID        uuid.UUID  `json:"id"`
	Version   int        `json:"version"`
	CreatedBy *uuid.UUID `json:"createdBy,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}

// APIToken is a bearer credential for programmatic access.
type APIToken struct {
	ID            uuid.UUID  `json:"id"`
	Name          string     `json:"name"`
	Prefix        string     `json:"prefix"`
	UserID        *uuid.UUID `json:"userId,omitempty"`
	Username      string     `json:"username,omitempty"`
	GroupID       *uuid.UUID `json:"groupId,omitempty"`
	GroupName     string     `json:"groupName,omitempty"`
	Scopes        []string   `json:"scopes"`
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
	LastUsedAt    *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt     *time.Time `json:"revokedAt,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	CreatedBy     *uuid.UUID `json:"createdBy,omitempty"`
	CreatedByName string     `json:"createdByName,omitempty"`
}

// AuditEntry records a security-relevant action.
type AuditEntry struct {
	ID         int64     `json:"id"`
	ActorLabel string    `json:"actorLabel"`
	Action     string    `json:"action"`
	TargetType string    `json:"targetType"`
	TargetID   string    `json:"targetId"`
	Detail     any       `json:"detail"`
	IP         string    `json:"ip"`
	CreatedAt  time.Time `json:"createdAt"`
}

// Settings is the single row describing the installation.
type Settings struct {
	Initialized  bool   `json:"initialized"`
	InstanceName string `json:"instanceName"`
	KeyID        string `json:"keyId"`
	KeyCheck     []byte `json:"-"`
}
