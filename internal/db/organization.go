// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	queryv1 "github.com/k8shell-io/common/pkg/api/gen/go/query/v1"
	"github.com/k8shell-io/common/pkg/db"
	"github.com/k8shell-io/common/pkg/models"
	pkgquery "github.com/k8shell-io/common/pkg/query"
)

// ErrOrganizationExists is returned by CreateOrganization when an
// organization with the same name already exists.
var ErrOrganizationExists = errors.New("organization already exists")

// ErrOrganizationNotFound is returned by DeleteOrganization when no
// organization with the given name exists.
var ErrOrganizationNotFound = errors.New("organization not found")

// ErrOrganizationInUse is returned by DeleteOrganization when at least one
// user still belongs to the organization. Org-scoped roles no longer block
// deletion — DeleteOrganization cascades those itself.
var ErrOrganizationInUse = errors.New("organization is still referenced by at least one user")

// ErrOrganizationReadOnly is returned by UpdateOrganization and
// DeleteOrganization when called against DefaultOrganizationName.
var ErrOrganizationReadOnly = errors.New("organization is read-only and cannot be modified")

// DefaultOrganizationName is the built-in organization every k8Shell
// deployment is seeded with (see db/migrations/000001_schema.up.sql), and
// the only organization whose models.Organization.ReadOnly is true — it
// can never be updated or deleted, since it's the fallback organization the
// system itself depends on existing.
const DefaultOrganizationName = "default"

// CreateOrganization registers a new organization.
func (d *DB) CreateOrganization(name, description string) (*models.Organization, error) {
	org := &models.Organization{Name: name, Description: description, ReadOnly: name == DefaultOrganizationName}
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
// organization with that name exists, or ErrOrganizationReadOnly for
// DefaultOrganizationName.
func (d *DB) UpdateOrganization(name string, description *string) (*models.Organization, error) {
	if name == DefaultOrganizationName {
		return nil, fmt.Errorf("%w: %q", ErrOrganizationReadOnly, name)
	}

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
// AdminUsernames and UserCount are computed rather than stored: AdminUsernames
// lists the org's users holding orgAdminRoleName (there may be zero, one, or
// many; see OrganizationAdminUsernamesExpr), and UserCount is the total
// number of users in the org, computed via a join/aggregate in a single
// query rather than N+1 per-org lookups.
func (d *DB) ListOrganizations() ([]*models.Organization, error) {
	sqlQuery := organizationsSelectSQL + "GROUP BY o.name, o.description, o.created_at\nORDER BY o.name"

	rows, err := d.Pool.Query(context.Background(), sqlQuery, orgAdminRoleName)
	if err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}
	defer rows.Close()

	return scanOrganizations(rows)
}

// GetOrganization retrieves a single organization by name, with the same
// computed AdminUsernames/UserCount fields as ListOrganizations. Returns
// ErrOrganizationNotFound when no organization with that name exists.
func (d *DB) GetOrganization(name string) (*models.Organization, error) {
	sqlQuery := organizationsSelectSQL + "WHERE o.name = $2\nGROUP BY o.name, o.description, o.created_at"

	var org models.Organization
	err := d.Pool.QueryRow(context.Background(), sqlQuery, orgAdminRoleName, name).Scan(
		&org.Name, &org.Description, &org.CreatedAt, &org.AdminUsernames, &org.UserCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: %q", ErrOrganizationNotFound, name)
	}
	if err != nil {
		return nil, fmt.Errorf("get organization: %w", err)
	}
	org.ReadOnly = org.Name == DefaultOrganizationName

	return &org, nil
}

// OrganizationAdminUsernamesExpr computes an organization's org-admin
// usernames as a self-contained correlated subquery, independent of any
// join/GROUP BY in the enclosing query — the same shape as UserBlueprintsExpr
// above, and for the same reason: array_agg(...) FILTER (...) is an
// aggregate tied to the enclosing query's own GROUP BY, so it can only be
// referenced in that query's own SELECT list, never repeated inside a WHERE
// or HAVING filter condition. A correlated subquery has no such
// restriction, so it's reused as-is by both ListOrganizations/
// ListOrganizationsQuery's SELECT list and organizationsQueryFieldMap's
// adminUsernames filter. Every query using this must bind orgAdminRoleName
// as its first ($1) parameter, and every query selecting from
// identity.organizations must alias the table as "o" for this to resolve.
const OrganizationAdminUsernamesExpr = `COALESCE((
	SELECT array_agg(au.username ORDER BY au.username)
	FROM identity.users au
	WHERE au.organization = o.name AND $1 = ANY(au.roles)
), ARRAY[]::varchar[])`

// organizationsSelectSQL is the shared SELECT/FROM/JOIN header for
// ListOrganizations and ListOrganizationsQuery: AdminUsernames is computed
// by OrganizationAdminUsernamesExpr, and UserCount via a LEFT JOIN/GROUP BY
// against identity.users, aliased "o"/"u" so callers can add WHERE/HAVING
// conditions unambiguously.
const organizationsSelectSQL = `
	SELECT
		o.name,
		COALESCE(o.description, ''),
		o.created_at,
		` + OrganizationAdminUsernamesExpr + `,
		COUNT(u.username)
	FROM identity.organizations o
	LEFT JOIN identity.users u ON u.organization = o.name
`

// ListOrganizationsQuery returns organizations matching a generic
// query.v1.Payload, built against desc/fm via common/pkg/query. Callers
// must have already run query.Validate(desc, payload) — ListOrganizationsQuery
// trusts the payload has been checked and only translates it to SQL.
//
// query.BuildQuery can't be used directly here: it appends WHERE immediately
// after the supplied "SELECT ... FROM ..." header, but organizationsQueryDescriptor
// includes userCount, a COUNT(u.username) aggregate — Postgres only allows
// aggregates to be filtered in a HAVING clause, evaluated after GROUP BY,
// never in WHERE. So every condition (not just userCount's) is applied as a
// single HAVING instead: query.BuildWhere/query.BuildOrderBy build the
// fragments, which are then spliced in after an explicit GROUP BY rather
// than before it. This is valid for the other fields too: name/description/
// createdAt are each also a GROUP BY key, so referencing one bare in HAVING
// is functionally dependent and unambiguous per group; adminUsernames
// resolves to OrganizationAdminUsernamesExpr, a correlated subquery that
// only reads o.name (itself a GROUP BY key) and has no aggregation tied to
// this query's own GROUP BY, so it's likewise safe to reference from HAVING
// — unlike ListUsersQuery, which has no aggregation at all and uses
// query.BuildQuery as-is with a normal WHERE.
//
// obligationOrgs is parsed by the caller from the payload's authz
// obligations (see common/pkg/authz.ParseOrgsObligation) and is enforced as
// a mandatory AND onto the Filters-derived HAVING, regardless of the
// client's own Filters.op — an obligation must never be diluted by a
// client-chosen OR.
func (d *DB) ListOrganizationsQuery(desc *queryv1.Descriptor, fm pkgquery.FieldMap, payload *queryv1.Payload,
	obligationOrgs []string) ([]*models.Organization, error) {
	limit, offset := db.AdjustListLimit(int(payload.GetPage().GetLimit()), int(payload.GetPage().GetOffset()))

	// $1 is reserved for orgAdminRoleName, used inside the SELECT's
	// OrganizationAdminUsernamesExpr subquery; HAVING/mandatory args are
	// numbered starting from $2.
	args := []any{orgAdminRoleName}
	having, havingArgs, err := pkgquery.BuildWhere(desc, fm, payload.GetFilters(), len(args))
	if err != nil {
		return nil, err
	}
	args = append(args, havingArgs...)

	var conditions []string
	if having != "" {
		conditions = append(conditions, "("+having+")")
	}
	if len(obligationOrgs) > 0 {
		args = append(args, obligationOrgs)
		conditions = append(conditions, fmt.Sprintf("o.name = ANY($%d)", len(args)))
	}

	sqlQuery := organizationsSelectSQL
	sqlQuery += "GROUP BY o.name, o.description, o.created_at\n"
	if len(conditions) > 0 {
		sqlQuery += "HAVING " + strings.Join(conditions, " AND ") + "\n"
	}

	if orderBy := pkgquery.BuildOrderBy(desc, fm, payload.GetSort()); orderBy != "" {
		sqlQuery += "ORDER BY " + orderBy + "\n"
	}

	args = append(args, limit, offset)
	sqlQuery += fmt.Sprintf("LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := d.Pool.Query(context.Background(), sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("query organizations: %w", err)
	}
	defer rows.Close()

	return scanOrganizations(rows)
}

func scanOrganizations(rows pgx.Rows) ([]*models.Organization, error) {
	var orgs []*models.Organization
	for rows.Next() {
		var org models.Organization
		if err := rows.Scan(&org.Name, &org.Description, &org.CreatedAt,
			&org.AdminUsernames, &org.UserCount); err != nil {
			return nil, err
		}
		org.ReadOnly = org.Name == DefaultOrganizationName
		orgs = append(orgs, &org)
	}
	return orgs, rows.Err()
}

// DeleteOrganization removes an organization from the registry, cascading
// its org-scoped roles and their role_blueprints — mirroring DeleteRole's
// own role_blueprints cleanup, just applied in bulk to every role scoped to
// this org instead of one at a time, since a role (and its granted
// blueprints) has no meaning once the org it's scoped to is gone. Its
// onboard_rules are cascaded for the same reason: org there is a NOT NULL
// destination, not an optional scope, so a rule naming this org has nothing
// left to place users into once it's gone.
//
// Any user still belonging to the org is deliberately not cascaded:
// identity.users.organization carries a NOT NULL foreign key to
// identity.organizations(name) with no ON DELETE CASCADE, so Postgres
// itself refuses the delete while any user remains — that FK violation is
// translated to ErrOrganizationInUse. Deleting user accounts (and their
// credentials, access tokens, POSIX identity) is a much more destructive
// decision than pruning role definitions, and this method does not make it
// on the caller's behalf; the caller must reassign or delete those users
// first.
//
// Returns ErrOrganizationReadOnly for DefaultOrganizationName without
// touching the database — it can never be deleted.
func (d *DB) DeleteOrganization(name string) error {
	if name == DefaultOrganizationName {
		return fmt.Errorf("%w: %q", ErrOrganizationReadOnly, name)
	}

	ctx := context.Background()

	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			d.log.Error().Err(err).Msg("rollback transaction")
		}
	}()

	if _, err := tx.Exec(ctx,
		`DELETE FROM identity.role_blueprints WHERE org=$1`, name); err != nil {
		return fmt.Errorf("delete organization role blueprints: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`DELETE FROM identity.roles WHERE org=$1`, name); err != nil {
		return fmt.Errorf("delete organization roles: %w", err)
	}

	// onboard_rules.org is a NOT NULL destination (see
	// db/migrations/000002_onboard_rules.up.sql), not an optional scope —
	// a rule that places users into this org has no meaning once the org
	// is gone, so it's cascaded here the same way role/role_blueprints are,
	// rather than blocking the delete like a real user account would.
	if _, err := tx.Exec(ctx,
		`DELETE FROM identity.onboard_rules WHERE org=$1`, name); err != nil {
		return fmt.Errorf("delete organization onboard rules: %w", err)
	}

	result, err := tx.Exec(ctx, `DELETE FROM identity.organizations WHERE name=$1`, name)
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

	return tx.Commit(ctx)
}
