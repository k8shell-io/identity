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

// ErrOrganizationExists is returned by CreateOrganization when an
// organization with the same name already exists.
var ErrOrganizationExists = errors.New("organization already exists")

// ErrOrganizationNotFound is returned by DeleteOrganization when no
// organization with the given name exists.
var ErrOrganizationNotFound = errors.New("organization not found")

// ErrOrganizationInUse is returned by DeleteOrganization when at least one
// user or role still references the organization.
var ErrOrganizationInUse = errors.New("organization is still referenced by at least one user or role")

// CreateOrganization registers a new organization.
func (d *DB) CreateOrganization(name, description string) (*models.Organization, error) {
	org := &models.Organization{Name: name, Description: description}
	err := d.Pool.QueryRow(context.Background(),
		`INSERT INTO identity.organizations (name, description)
		 VALUES ($1, $2)
		 RETURNING created_at`,
		name, description,
	).Scan(&org.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "organizations_pkey" {
			return nil, fmt.Errorf("%w: %q", ErrOrganizationExists, name)
		}
		return nil, fmt.Errorf("insert organization: %w", err)
	}

	return org, nil
}

// UpdateOrganization updates an organization's description. The name is
// immutable and used only to identify the organization; pass a nil
// description to leave it unchanged. Returns ErrOrganizationNotFound when no
// organization with that name exists.
func (d *DB) UpdateOrganization(name string, description *string) (*models.Organization, error) {
	org := &models.Organization{Name: name}
	err := d.Pool.QueryRow(context.Background(),
		`UPDATE identity.organizations SET description = COALESCE($2, description)
		 WHERE name=$1
		 RETURNING COALESCE(description, ''), created_at`,
		name, description,
	).Scan(&org.Description, &org.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: %q", ErrOrganizationNotFound, name)
	}
	if err != nil {
		return nil, fmt.Errorf("update organization: %w", err)
	}

	return org, nil
}

// ListOrganizations returns every registered organization, ordered by name.
// AdminUsernames and UserCount are computed via a left join against
// identity.users rather than stored: AdminUsernames lists the org's users
// holding orgAdminRoleName (there may be zero, one, or many), and UserCount
// is the total number of users in the org, joined and aggregated in a
// single query rather than N+1 per-org lookups.
func (d *DB) ListOrganizations() ([]*models.Organization, error) {
	rows, err := d.Pool.Query(context.Background(),
		`SELECT
			o.name,
			COALESCE(o.description, ''),
			o.created_at,
			COALESCE(array_agg(u.username ORDER BY u.username) FILTER (WHERE $1 = ANY(u.roles)), ARRAY[]::varchar[]),
			COUNT(u.username)
		FROM identity.organizations o
		LEFT JOIN identity.users u ON u.organization = o.name
		GROUP BY o.name, o.description, o.created_at
		ORDER BY o.name`,
		orgAdminRoleName)
	if err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}
	defer rows.Close()

	var orgs []*models.Organization
	for rows.Next() {
		var org models.Organization
		if err := rows.Scan(&org.Name, &org.Description, &org.CreatedAt,
			&org.AdminUsernames, &org.UserCount); err != nil {
			return nil, err
		}
		orgs = append(orgs, &org)
	}
	return orgs, rows.Err()
}

// DeleteOrganization removes an organization from the registry. Both
// identity.users.organization and identity.roles.org carry a foreign key
// referencing this table (with no ON DELETE CASCADE), so Postgres itself
// refuses the delete while any row still references it — that FK violation
// is translated to ErrOrganizationInUse rather than requiring an explicit
// pre-check.
func (d *DB) DeleteOrganization(name string) error {
	result, err := d.Pool.Exec(context.Background(), `DELETE FROM identity.organizations WHERE name=$1`, name)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return fmt.Errorf("%w: %q", ErrOrganizationInUse, name)
		}
		return fmt.Errorf("delete organization: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("%w: %q", ErrOrganizationNotFound, name)
	}
	return nil
}
