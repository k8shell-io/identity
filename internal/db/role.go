// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/k8shell-io/common/pkg/models"
)

// ErrRoleExists is returned by CreateRole when a role with the same name
// already exists.
var ErrRoleExists = errors.New("role already exists")

// ErrRoleNotFound is returned by DeleteRole when no role with the given name exists.
var ErrRoleNotFound = errors.New("role not found")

// ErrRoleInUse is returned by DeleteRole when at least one user still holds the role.
var ErrRoleInUse = errors.New("role is still assigned to at least one user")

// orgAdminRoleName is the seeded baseline role (see 000001_schema.up.sql)
// that marks a user as an administrator of their organization. Used by
// ListOrganizations to compute each organization's admin_usernames.
const orgAdminRoleName = "org-admin"

// CreateRole registers a new assignable role. org may be empty, meaning the
// role is global (assignable regardless of a user's organization). The same
// name may be registered independently by different organizations — only
// (name, org) together must be unique, enforced by idx_roles_org_name and,
// for global roles, idx_roles_global_name_uniq.
func (d *DB) CreateRole(name, description, org string) (*models.RoleInfo, error) {
	var orgVal *string
	if org != "" {
		orgVal = &org
	}

	role := &models.RoleInfo{Name: name, Description: description, Org: org}
	err := d.Pool.QueryRow(context.Background(),
		`INSERT INTO identity.roles (name, description, org)
		 VALUES ($1, $2, $3)
		 RETURNING created_at`,
		name, description, orgVal,
	).Scan(&role.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch {
			case pgErr.Code == "23505" && (pgErr.ConstraintName == "idx_roles_org_name" || pgErr.ConstraintName == "idx_roles_global_name_uniq"):
				return nil, fmt.Errorf("%w: %q", ErrRoleExists, name)
			case pgErr.Code == "23503" && pgErr.ConstraintName == "roles_org_fkey":
				return nil, fmt.Errorf("%w: organization '%s' does not exist", models.ErrInvalidParameters, org)
			}
		}
		return nil, fmt.Errorf("insert role: %w", err)
	}

	return role, nil
}

// UpdateRole updates a role's description. Name and org together identify
// the role and are immutable; pass a nil description to leave it unchanged.
// org must match exactly (empty means the global role, not "any org").
// Returns ErrRoleNotFound when no matching role exists.
func (d *DB) UpdateRole(name, org string, description *string) (*models.RoleInfo, error) {
	var orgVal *string
	if org != "" {
		orgVal = &org
	}

	role := &models.RoleInfo{Name: name, Org: org}
	err := d.Pool.QueryRow(context.Background(),
		`UPDATE identity.roles SET description = COALESCE($3, description)
		 WHERE name=$1 AND org IS NOT DISTINCT FROM $2
		 RETURNING COALESCE(description, ''), created_at`,
		name, orgVal, description,
	).Scan(&role.Description, &role.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: %q", ErrRoleNotFound, name)
	}
	if err != nil {
		return nil, fmt.Errorf("update role: %w", err)
	}

	return role, nil
}

// rolesBaseQuery selects a role registry row alongside its computed
// UserCount. UserCount is computed via a left join against identity.users
// rather than stored: identity.users has no index on roles, so joining
// role-per-role (r.name = ANY(u.roles)) would rescan the users table once
// per role; unnesting each user's roles once up front and joining on
// equality instead scans identity.users a single time regardless of role
// count. Callers append a WHERE clause and must keep the GROUP BY/ORDER BY
// suffix below.
const rolesBaseQuery = `SELECT r.name, COALESCE(r.description, ''), COALESCE(r.org, ''), r.created_at, COUNT(ur.username)
	FROM identity.roles r
	LEFT JOIN (SELECT username, unnest(roles) AS role_name FROM identity.users) ur
		ON ur.role_name = r.name`

const rolesGroupOrderSuffix = ` GROUP BY r.name, r.description, r.org, r.created_at ORDER BY r.name`

// scanRoleRows reads the rows produced by rolesBaseQuery into RoleInfo values.
func scanRoleRows(rows pgx.Rows) ([]*models.RoleInfo, error) {
	defer rows.Close()

	var roles []*models.RoleInfo
	for rows.Next() {
		var role models.RoleInfo
		if err := rows.Scan(&role.Name, &role.Description, &role.Org, &role.CreatedAt, &role.UserCount); err != nil {
			return nil, err
		}
		roles = append(roles, &role)
	}
	return roles, rows.Err()
}

// ListRoles returns the roles assignable within org, ordered by name: those
// scoped to org plus all global roles (org IS NULL) — an org-scoped caller
// must still see the global roles it may assign. org must be non-empty; use
// ListGlobalRoles to list global roles on their own.
func (d *DB) ListRoles(org string) ([]*models.RoleInfo, error) {
	query := rolesBaseQuery + ` WHERE r.org = $1 OR r.org IS NULL` + rolesGroupOrderSuffix

	rows, err := d.Pool.Query(context.Background(), query, org)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	return scanRoleRows(rows)
}

// ListGlobalRoles returns the roles assignable across every organization
// (org IS NULL), ordered by name.
func (d *DB) ListGlobalRoles() ([]*models.RoleInfo, error) {
	query := rolesBaseQuery + ` WHERE r.org IS NULL` + rolesGroupOrderSuffix

	rows, err := d.Pool.Query(context.Background(), query)
	if err != nil {
		return nil, fmt.Errorf("list global roles: %w", err)
	}
	return scanRoleRows(rows)
}

// DeleteRole removes a role from the registry, refusing to do so while any
// user still holds it — a silent privilege change (cascading the role off
// every user that has it) is worse than a failed call. org must match
// exactly (empty means the global role, not "any org"); the in-use check
// itself is by name only, since identity.users.roles stores plain names
// without an org qualifier.
func (d *DB) DeleteRole(name, org string) error {
	ctx := context.Background()

	var orgVal *string
	if org != "" {
		orgVal = &org
	}

	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			d.log.Error().Err(err).Msg("rollback transaction")
		}
	}()

	var inUse bool
	err = tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM identity.users WHERE $1 = ANY(roles))`, name,
	).Scan(&inUse)
	if err != nil {
		return fmt.Errorf("check role usage: %w", err)
	}
	if inUse {
		return fmt.Errorf("%w: %q", ErrRoleInUse, name)
	}

	result, err := tx.Exec(ctx,
		`DELETE FROM identity.roles WHERE name=$1 AND org IS NOT DISTINCT FROM $2`, name, orgVal)
	if err != nil {
		return fmt.Errorf("delete role: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("%w: %q", ErrRoleNotFound, name)
	}

	return tx.Commit(ctx)
}

// MissingRoles reports which of the given role names are not registered in
// identity.roles, preserving names as given (deduplicated). Used to validate
// role assignment in bulk so a single error can name every offending role at
// once rather than failing one at a time.
func (d *DB) MissingRoles(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}

	rows, err := d.Pool.Query(context.Background(),
		`SELECT name FROM identity.roles WHERE name = ANY($1)`, names)
	if err != nil {
		return nil, fmt.Errorf("check known roles: %w", err)
	}
	defer rows.Close()

	found := make(map[string]struct{})
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		found[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	seen := make(map[string]struct{}, len(names))
	var missing []string
	for _, n := range names {
		if _, ok := found[n]; ok {
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		missing = append(missing, n)
	}
	return missing, nil
}
