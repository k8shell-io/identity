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

// FindUser retrieves a user by username. If source is empty, the search is not filtered by source.
func (d *DB) FindUser(username string, source string) (*models.User, error) {
	var (
		query string
		args  []any
	)
	if source == "" {
		query = `
			SELECT username, is_valid, expires_at, uid, gid, fullname,
			       email, password, shell, sudo, locked,
			       roles, blueprints, source, organization
			FROM identity.users
			WHERE username=$1
		`
		args = []any{username}
	} else {
		query = `
			SELECT username, is_valid, expires_at, uid, gid, fullname,
			       email, password, shell, sudo, locked,
			       roles, blueprints, source, organization
			FROM identity.users
			WHERE username=$1 AND source=$2
		`
		args = []any{username, source}
	}

	var user models.User
	err := d.Pool.QueryRow(context.Background(), query, args...).Scan(
		&user.Username,
		&user.IsValid,
		&user.ExpiresAt,
		&user.UID,
		&user.GID,
		&user.Fullname,
		&user.Email,
		&user.Password,
		&user.Shell,
		&user.Sudo,
		&user.Locked,
		&user.Roles,
		&user.Blueprints,
		&user.Source,
		&user.Organization,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrUserNotFound
	} else if err != nil {
		return nil, err
	}

	return &user, nil
}

// FindUserByEmail retrieves a user by exact email match. Returns
// models.ErrUserNotFound when no user has that email, or when email is empty.
func (d *DB) FindUserByEmail(email string) (*models.User, error) {
	if email == "" {
		return nil, models.ErrUserNotFound
	}

	query := `
		SELECT username, is_valid, expires_at, uid, gid, fullname,
		       email, password, shell, sudo, locked,
		       roles, blueprints, source, organization
		FROM identity.users
		WHERE email=$1
	`

	var user models.User
	err := d.Pool.QueryRow(context.Background(), query, email).Scan(
		&user.Username,
		&user.IsValid,
		&user.ExpiresAt,
		&user.UID,
		&user.GID,
		&user.Fullname,
		&user.Email,
		&user.Password,
		&user.Shell,
		&user.Sudo,
		&user.Locked,
		&user.Roles,
		&user.Blueprints,
		&user.Source,
		&user.Organization,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrUserNotFound
	} else if err != nil {
		return nil, err
	}

	return &user, nil
}

// FindUserByUsernameAndSource retrieves a user by username and source.
func (d *DB) FindUserByUsernameAndSource(ctx context.Context, username string, source string) (*models.User, error) {
	query := `
		SELECT username, is_valid, expires_at, uid, gid, fullname,
		       email, COALESCE(password, '') AS password, shell, sudo, locked,
		       roles, blueprints, source, organization
		FROM identity.users
		WHERE username=$1 and source=$2
	`

	var user models.User
	err := d.Pool.QueryRow(ctx, query, username, source).Scan(
		&user.Username,
		&user.IsValid,
		&user.ExpiresAt,
		&user.UID,
		&user.GID,
		&user.Fullname,
		&user.Email,
		&user.Password,
		&user.Shell,
		&user.Sudo,
		&user.Locked,
		&user.Roles,
		&user.Blueprints,
		&user.Source,
		&user.Organization,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrUserNotFound
	} else if err != nil {
		return nil, err
	}

	return &user, nil
}

// ErrUsernameExists is returned by CreateUser when the username is already taken.
var ErrUsernameExists = errors.New("username already exists")

// ErrUIDExists is returned by CreateUser when the uid is already in use by another user.
var ErrUIDExists = errors.New("uid already exists")

// ErrEmailExists is returned by CreateUser when the email is already in use by another user.
var ErrEmailExists = errors.New("email already exists")

// CreateUser inserts a new user record into the database.
// If the user's organization does not exist and is in the auto-create allowlist,
// it is created automatically. Otherwise the insert will fail if the org is missing.
func (d *DB) CreateUser(user *models.User) error {
	ctx := context.Background()

	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		err := tx.Rollback(ctx)
		if err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			d.log.Error().Err(err).Msg("rollback transaction")
		}
	}()

	if d.orgAutoCreateAllowed(user.Organization) {
		_, err = tx.Exec(ctx,
			`INSERT INTO identity.organizations (name, description)
			 VALUES ($1, '')
			 ON CONFLICT (name) DO NOTHING`,
			user.Organization)
		if err != nil {
			return fmt.Errorf("ensure organization: %w", err)
		}
	}

	_, err = tx.Exec(ctx, `INSERT INTO identity.users (
		username, is_valid, expires_at, uid, gid, fullname,
		email, password, shell, sudo, locked,
		roles, blueprints, source, organization
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
	)`,
		user.Username, user.IsValid, user.ExpiresAt, user.UID, user.GID, user.Fullname,
		user.Email, user.Password, user.Shell, user.Sudo, user.Locked,
		user.Roles, user.Blueprints, user.Source, user.Organization)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			switch pgErr.ConstraintName {
			case "users_pkey":
				return fmt.Errorf("%w: %q", ErrUsernameExists, user.Username)
			case "users_uid_key":
				return fmt.Errorf("%w: %d", ErrUIDExists, user.UID)
			case "idx_users_email_unique":
				return fmt.Errorf("%w: %q", ErrEmailExists, user.Email)
			}
		}
		if errors.As(err, &pgErr) && pgErr.Code == "23503" && pgErr.ConstraintName == "users_organization_fkey" {
			return fmt.Errorf("%w: organization '%s' does not exist", models.ErrInvalidParameters, user.Organization)
		}
		return err
	}

	return tx.Commit(ctx)
}

// localUserUIDFloor and localUserUIDCeiling bound the UID range auto-assigned
// by NextAvailableUID for users created via CreateUser, mirroring the
// UID_MIN/UID_MAX pair in /etc/login.defs that reserves a range for regular
// users apart from system accounts. Provider-synced users carry whatever
// numeric ID their upstream provider (GitHub, GitLab, etc.) assigned, which
// can be arbitrarily large; without a ceiling here, a single such UID inside
// the range would make MAX(uid) jump to it and every subsequent local
// allocation would chase that value upward instead of staying compact.
const (
	localUserUIDFloor   = 1000
	localUserUIDCeiling = 59999
)

// ErrUIDRangeExhausted is returned by NextAvailableUID when every UID in
// [localUserUIDFloor, localUserUIDCeiling] is already taken.
var ErrUIDRangeExhausted = errors.New("no available uid in local user range")

// NextAvailableUID returns the next unused UID in
// [localUserUIDFloor, localUserUIDCeiling], for assigning to users created
// via CreateUser that don't specify one. Because it only considers UIDs
// already taken within that bounded range, it stays collision-free and
// compact regardless of what UIDs providers have used elsewhere.
func (d *DB) NextAvailableUID() (uint32, error) {
	var uid uint32
	err := d.Pool.QueryRow(context.Background(),
		`SELECT COALESCE(MAX(uid), $1 - 1) + 1 FROM identity.users WHERE uid BETWEEN $1 AND $2`,
		localUserUIDFloor, localUserUIDCeiling).Scan(&uid)
	if err != nil {
		return 0, err
	}
	if uid > localUserUIDCeiling {
		return 0, ErrUIDRangeExhausted
	}
	return uid, nil
}

// UpdateUser updates an existing user's fields, identified by username.
func (d *DB) UpdateUser(user *models.User) error {
	query := `UPDATE identity.users SET
		is_valid=$1,
		expires_at=$2,
		uid=$3,
		gid=$4,
		fullname=$5,
		email=$6,
		password=$7,
		shell=$8,
		sudo=$9,
		locked=$10,
		roles=$11,
		blueprints=$12,
		source=$13,
		organization=$14
	WHERE username=$15`

	_, err := d.Pool.Exec(context.Background(), query,
		user.IsValid,
		user.ExpiresAt,
		user.UID,
		user.GID,
		user.Fullname,
		user.Email,
		user.Password,
		user.Shell,
		user.Sudo,
		user.Locked,
		user.Roles,
		user.Blueprints,
		user.Source,
		user.Organization,
		user.Username,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" && pgErr.ConstraintName == "users_organization_fkey" {
			return fmt.Errorf("%w: organization '%s' does not exist", models.ErrInvalidParameters, user.Organization)
		}
		return err
	}
	return nil
}

// SetUserPassword sets a user's stored password hash. Pass an empty hash to
// clear it (NULL), which disables password auth for the user.
func (d *DB) SetUserPassword(username, hash string) (*models.User, error) {
	var val *string
	if hash != "" {
		val = &hash
	}

	result, err := d.Pool.Exec(context.Background(),
		`UPDATE identity.users SET password=$2 WHERE username=$1`, username, val)
	if err != nil {
		return nil, err
	}
	if result.RowsAffected() == 0 {
		return nil, models.ErrUserNotFound
	}

	return d.FindUser(username, "")
}

// InvalidateUser marks a user account as invalid (is_valid=false) without deleting it.
func (d *DB) InvalidateUser(username string) error {
	query := `UPDATE identity.users SET is_valid=false WHERE username=$1`
	_, err := d.Pool.Exec(context.Background(), query, username)
	return err
}

// DeleteUser permanently removes a user record from the database by
// username. Credentials and access tokens owned by the user are removed
// along with it (ON DELETE CASCADE).
func (d *DB) DeleteUser(username string) error {
	result, err := d.Pool.Exec(context.Background(), `DELETE FROM identity.users WHERE username=$1`, username)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return models.ErrUserNotFound
	}
	return nil
}

// ListUsers returns a paginated list of users ordered by username, optionally
// restricted to users matching the given filters. roles and blueprints match
// when the user has at least one of the listed values; org matches when the
// user belongs to that organization. An empty/nil filter imposes no
// restriction on that dimension.
func (d *DB) ListUsers(limit, offset int, roles, blueprints []string, org string) ([]*models.User, error) {
	limit, offset = db.AdjustListLimit(limit, offset)

	query := `
		SELECT username, is_valid, expires_at, uid, gid, fullname,
		       email, COALESCE(password, '') AS password, shell, sudo, locked,
		       roles, blueprints, source, organization
		FROM identity.users
	`

	var (
		conditions []string
		args       []any
	)
	if len(roles) > 0 {
		args = append(args, roles)
		conditions = append(conditions, fmt.Sprintf("roles && $%d", len(args)))
	}
	if len(blueprints) > 0 {
		args = append(args, blueprints)
		conditions = append(conditions, fmt.Sprintf("blueprints && $%d", len(args)))
	}
	if org != "" {
		args = append(args, org)
		conditions = append(conditions, fmt.Sprintf("organization = $%d", len(args)))
	}
	if len(conditions) > 0 {
		query += "WHERE " + strings.Join(conditions, " AND ") + "\n"
	}

	args = append(args, limit, offset)
	query += fmt.Sprintf("ORDER BY username LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := d.Pool.Query(context.Background(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanUsers(rows)
}

// ListUsersQuery returns a paginated list of users matching a generic
// query.v1.Payload, built against desc/fm via common/pkg/query. Callers
// must have already run query.Validate(desc, payload) — ListUsersQuery
// trusts the payload has been checked and only translates it to SQL.
//
// obligationRoles/obligationBlueprints/obligationOrg are parsed by the
// caller from the payload's authz obligations (see
// common/pkg/authz Parse{Roles,Blueprints,Org}Obligation) and are enforced
// as a mandatory AND onto the Filters-derived WHERE, regardless of the
// client's own Filters.op — an obligation must never be diluted by a
// client-chosen OR.
func (d *DB) ListUsersQuery(desc *queryv1.Descriptor, fm pkgquery.FieldMap, payload *queryv1.Payload,
	obligationRoles, obligationBlueprints []string, obligationOrg string) ([]*models.User, error) {
	limit, offset := db.AdjustListLimit(int(payload.GetPage().GetLimit()), int(payload.GetPage().GetOffset()))

	const selectSQL = `
		SELECT username, is_valid, expires_at, uid, gid, fullname,
		       email, COALESCE(password, '') AS password, shell, sudo, locked,
		       roles, blueprints, source, organization
		FROM identity.users
	`

	mandatory := []pkgquery.Mandatory{
		{Column: "roles", Array: true, Values: obligationRoles},
		{Column: "blueprints", Array: true, Values: obligationBlueprints},
	}
	if obligationOrg != "" {
		mandatory = append(mandatory, pkgquery.Mandatory{Column: "organization", Values: []string{obligationOrg}})
	}

	sqlQuery, args, err := pkgquery.BuildQuery(selectSQL, desc, fm, payload, mandatory, limit, offset)
	if err != nil {
		return nil, err
	}

	rows, err := d.Pool.Query(context.Background(), sqlQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanUsers(rows)
}

func scanUsers(rows pgx.Rows) ([]*models.User, error) {
	var users []*models.User
	for rows.Next() {
		var user models.User
		if err := rows.Scan(
			&user.Username,
			&user.IsValid,
			&user.ExpiresAt,
			&user.UID,
			&user.GID,
			&user.Fullname,
			&user.Email,
			&user.Password,
			&user.Shell,
			&user.Sudo,
			&user.Locked,
			&user.Roles,
			&user.Blueprints,
			&user.Source,
			&user.Organization,
		); err != nil {
			return nil, err
		}
		users = append(users, &user)
	}
	return users, nil
}

// ErrCredentialExists is returned by AddKubernetesUserCredential, AddGitUserCredential, and
// AddRegistryUserCredential when a credential already exists for the same uniqueness key.
var ErrCredentialExists = errors.New("credential already exists")

// AddKubernetesUserCredential provisions a Kubernetes service-account credential for a user.
// namespace maps to service_scope and serviceAccount maps to subject; the secret is left NULL
// since kubernetes credentials are resolved on demand via the TokenRequest API.
func (d *DB) AddKubernetesUserCredential(username, namespace, serviceAccount string) (*models.UserCredential, error) {
	if username == "" || namespace == "" || serviceAccount == "" {
		return nil, fmt.Errorf("required field: username, namespace, service_account")
	}

	query := `INSERT INTO identity.user_credentials (
		username, service_name, service_scope, subject, secret, credential_source
	) VALUES ($1, 'kubernetes', $2, $3, NULL, 'kubernetes')
	RETURNING id, is_active, created_at, updated_at`

	cred := &models.UserCredential{
		Username:         username,
		ServiceName:      "kubernetes",
		ServiceScope:     namespace,
		Subject:          serviceAccount,
		CredentialSource: "kubernetes",
	}
	err := d.Pool.QueryRow(context.Background(), query, username, namespace, serviceAccount).Scan(
		&cred.ID, &cred.IsActive, &cred.CreatedAt, &cred.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "user_credentials_uniq_key" {
			return nil, fmt.Errorf("%w for user '%s', namespace '%s'", ErrCredentialExists, username, namespace)
		}
		return nil, err
	}

	return cred, nil
}

// AddGitUserCredential stores a Git credential for a user. scope maps to service_scope and
// subject maps to subject; credential_source is always "stored" and secret is persisted as
// given. A user may have at most one credential per (service_name, scope), regardless of
// subject.
func (d *DB) AddGitUserCredential(username, scope, subject, secret string) (*models.UserCredential, error) {
	if username == "" || scope == "" || subject == "" || secret == "" {
		return nil, fmt.Errorf("required field: username, scope, subject, secret")
	}

	query := `INSERT INTO identity.user_credentials (
		username, service_name, service_scope, subject, secret, credential_source
	) VALUES ($1, 'git', $2, $3, $4, 'stored')
	RETURNING id, is_active, created_at, updated_at`

	cred := &models.UserCredential{
		Username:         username,
		ServiceName:      "git",
		ServiceScope:     scope,
		Subject:          subject,
		Secret:           secret,
		CredentialSource: "stored",
	}
	err := d.Pool.QueryRow(context.Background(), query, username, scope, subject, secret).Scan(
		&cred.ID, &cred.IsActive, &cred.CreatedAt, &cred.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "user_credentials_uniq_key" {
			return nil, fmt.Errorf("%w for user '%s', scope '%s'", ErrCredentialExists, username, scope)
		}
		return nil, err
	}

	return cred, nil
}

// AddRegistryUserCredential stores a container registry credential for a user. scope maps to
// service_scope and subject maps to subject; credential_source is always "stored" and secret
// is persisted as given. A user may have at most one credential per (service_name, scope),
// regardless of subject.
func (d *DB) AddRegistryUserCredential(username, scope, subject, secret string) (*models.UserCredential, error) {
	if username == "" || scope == "" || subject == "" || secret == "" {
		return nil, fmt.Errorf("required field: username, scope, subject, secret")
	}

	query := `INSERT INTO identity.user_credentials (
		username, service_name, service_scope, subject, secret, credential_source
	) VALUES ($1, 'registry', $2, $3, $4, 'stored')
	RETURNING id, is_active, created_at, updated_at`

	cred := &models.UserCredential{
		Username:         username,
		ServiceName:      "registry",
		ServiceScope:     scope,
		Subject:          subject,
		Secret:           secret,
		CredentialSource: "stored",
	}
	err := d.Pool.QueryRow(context.Background(), query, username, scope, subject, secret).Scan(
		&cred.ID, &cred.IsActive, &cred.CreatedAt, &cred.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "user_credentials_uniq_key" {
			return nil, fmt.Errorf("%w for user '%s', scope '%s'", ErrCredentialExists, username, scope)
		}
		return nil, err
	}

	return cred, nil
}

// GetUserCredential retrieves a single credential for the given user,
// service_name and service_scope. Returns models.ErrUserNotFound when no
// matching active credential exists.
func (d *DB) GetUserCredential(username, serviceName, serviceScope string) (*models.UserCredential, error) {
	query := `SELECT id, username, service_name, service_scope, subject,
			COALESCE(secret, '') AS secret, credential_source, is_active, created_at, updated_at
		FROM identity.user_credentials
			WHERE username=$1 AND service_name=$2 AND service_scope=$3 AND is_active=true
		LIMIT 1`

	var cred models.UserCredential
	err := d.Pool.QueryRow(context.Background(), query, username, serviceName, serviceScope).Scan(
		&cred.ID,
		&cred.Username,
		&cred.ServiceName,
		&cred.ServiceScope,
		&cred.Subject,
		&cred.Secret,
		&cred.CredentialSource,
		&cred.IsActive,
		&cred.CreatedAt,
		&cred.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return &cred, nil
}

// ListUserCredentials retrieves all credentials for the given username. If id
// is non-zero, the result is filtered to the credential with that ID.
func (d *DB) ListUserCredentials(username string, id uint32) ([]*models.UserCredential, error) {
	query := `SELECT id, username, service_name, service_scope, subject,
			credential_source, is_active, created_at, updated_at
		FROM identity.user_credentials
			WHERE username=$1 AND ($2 = 0 OR id = $2)`

	rows, err := d.Pool.Query(context.Background(), query, username, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []*models.UserCredential
	for rows.Next() {
		var cred models.UserCredential
		if err := rows.Scan(
			&cred.ID,
			&cred.Username,
			&cred.ServiceName,
			&cred.ServiceScope,
			&cred.Subject,
			&cred.CredentialSource,
			&cred.IsActive,
			&cred.CreatedAt,
			&cred.UpdatedAt,
		); err != nil {
			return nil, err
		}
		creds = append(creds, &cred)
	}
	return creds, nil
}

// UpsertDynamicGitCredential inserts a dynamic git credential row for a user if one does not
// already exist for the given provider. serviceScope must be the provider address (URL) so that
// the git credentials helper can match credentials by URL. providerName is stored as
// credential_source so that ResolveCredential can route directly to the right IDP by name.
// The secret is NULL — the live token is fetched on demand from the provider via GetUserGitToken.
func (d *DB) UpsertDynamicGitCredential(username, providerName, serviceScope string) error {
	query := `INSERT INTO identity.user_credentials
		(username, service_name, service_scope, subject, secret, credential_source)
	VALUES ($1, 'git', $2, $1, NULL, $3)
	ON CONFLICT (username, service_name, service_scope) DO NOTHING`

	_, err := d.Pool.Exec(context.Background(), query, username, serviceScope, providerName)
	return err
}

// DeleteUserCredential removes a user credential by its ID.
func (d *DB) DeleteUserCredential(id uint32) error {
	result, err := d.Pool.Exec(context.Background(), `DELETE FROM identity.user_credentials WHERE id=$1`, id)
	if err != nil {
		return err
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("user credential with ID %d not found", id)
	}

	return nil
}

// ErrProtectedCredential is returned by UpdateUserCredential when the targeted credential
// was provisioned by the onboarding flow (credential_source LIKE 'idp.k8shell.io/%') and the
// caller tried to change something other than active.
var ErrProtectedCredential = errors.New("credential was created by the onboarding process; only active can be updated")

// RemoveUserCredential removes a single credential owned by username, identified by id.
// Returns models.ErrUserNotFound when no matching credential exists for that user.
func (d *DB) RemoveUserCredential(username string, id uint32) error {
	result, err := d.Pool.Exec(context.Background(),
		`DELETE FROM identity.user_credentials WHERE id=$1 AND username=$2`, id, username)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return models.ErrUserNotFound
	}
	return nil
}

// UpdateUserCredential updates an existing user credential record.
// For dynamic credentials (kubernetes, dynamic git) Secret is ignored — the
// secret column stays NULL and is resolved live at request time.
// UpdateUserCredential partially updates a credential identified by id. Nil arguments leave
// the corresponding column unchanged. Credentials whose credential_source matches
// "idp.k8shell.io/*" — provisioned by the onboarding flow (CompleteUserWebFlow /
// CompleteUserDeviceFlow) — may only have active updated; attempting to change scope,
// subject, or secret returns ErrProtectedCredential. Returns models.ErrUserNotFound when no
// credential with that id exists.
func (d *DB) UpdateUserCredential(id uint32, scope, subject, secret *string, active *bool) (*models.UserCredential, error) {
	var credentialSource string
	err := d.Pool.QueryRow(context.Background(),
		`SELECT credential_source FROM identity.user_credentials WHERE id=$1`, id,
	).Scan(&credentialSource)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	protected := strings.HasPrefix(credentialSource, "idp.k8shell.io/")
	if protected && (scope != nil || subject != nil || secret != nil) {
		return nil, ErrProtectedCredential
	}

	query := `UPDATE identity.user_credentials SET
			service_scope = COALESCE($2, service_scope),
			subject       = COALESCE($3, subject),
			secret        = COALESCE($4, secret),
			is_active     = COALESCE($5, is_active),
			updated_at    = NOW()
		WHERE id=$1
		RETURNING id, username, service_name, service_scope, subject,
			COALESCE(secret, '') AS secret, credential_source, is_active, created_at, updated_at`

	var cred models.UserCredential
	err = d.Pool.QueryRow(context.Background(), query, id, scope, subject, secret, active).Scan(
		&cred.ID,
		&cred.Username,
		&cred.ServiceName,
		&cred.ServiceScope,
		&cred.Subject,
		&cred.Secret,
		&cred.CredentialSource,
		&cred.IsActive,
		&cred.CreatedAt,
		&cred.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("credential update conflicts with an existing credential for the same scope/subject")
		}
		return nil, err
	}

	return &cred, nil
}

// addUserArrayField appends items to a user's text[] column (no duplicates) and returns the updated user.
func (d *DB) addUserArrayField(username, column string, items []string) (*models.User, error) {
	query := fmt.Sprintf(`UPDATE identity.users
		SET %s = array(SELECT unnest(%s) UNION SELECT unnest($2::text[]))
		WHERE username=$1`, column, column)
	result, err := d.Pool.Exec(context.Background(), query, username, items)
	if err != nil {
		return nil, err
	}
	if result.RowsAffected() == 0 {
		return nil, models.ErrUserNotFound
	}
	return d.FindUser(username, "")
}

// removeUserArrayField removes items from a user's text[] column and returns the updated user.
func (d *DB) removeUserArrayField(username, column string, items []string) (*models.User, error) {
	query := fmt.Sprintf(`UPDATE identity.users
		SET %s = array(SELECT unnest(%s) EXCEPT SELECT unnest($2::text[]))
		WHERE username=$1`, column, column)
	result, err := d.Pool.Exec(context.Background(), query, username, items)
	if err != nil {
		return nil, err
	}
	if result.RowsAffected() == 0 {
		return nil, models.ErrUserNotFound
	}
	return d.FindUser(username, "")
}

// AddUserRoles appends the given roles to the user, skipping duplicates.
func (d *DB) AddUserRoles(username string, roles []string) (*models.User, error) {
	return d.addUserArrayField(username, "roles", roles)
}

// RemoveUserRoles removes the given roles from the user.
func (d *DB) RemoveUserRoles(username string, roles []string) (*models.User, error) {
	return d.removeUserArrayField(username, "roles", roles)
}

// AddUserBlueprints appends the given blueprints to the user, skipping duplicates.
func (d *DB) AddUserBlueprints(username string, blueprints []string) (*models.User, error) {
	return d.addUserArrayField(username, "blueprints", blueprints)
}

// RemoveUserBlueprints removes the given blueprints from the user.
func (d *DB) RemoveUserBlueprints(username string, blueprints []string) (*models.User, error) {
	return d.removeUserArrayField(username, "blueprints", blueprints)
}

// ListUserAuthKeys returns the SSH public keys stored for a user, in the
// stable order relied on by index-based removal (RemoveUserAuthKey).
func (d *DB) ListUserAuthKeys(username string) ([]string, error) {
	var keys []string
	err := d.Pool.QueryRow(context.Background(),
		`SELECT auth_keys FROM identity.users WHERE username=$1`, username).Scan(&keys)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrUserNotFound
	} else if err != nil {
		return nil, err
	}
	return keys, nil
}

// SetUserAuthKeys replaces all SSH public keys stored for a user.
func (d *DB) SetUserAuthKeys(username string, authKeys []string) error {
	result, err := d.Pool.Exec(context.Background(),
		`UPDATE identity.users SET auth_keys=$2 WHERE username=$1`, username, authKeys)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return models.ErrUserNotFound
	}
	return nil
}

// ErrAuthKeyExists is returned by AddUserAuthKeys when one of the given keys
// is already registered for the user.
var ErrAuthKeyExists = errors.New("auth key already exists")

// AddUserAuthKeys appends the given SSH public keys to the user, preserving
// the existing order, then returns the updated user. It returns
// ErrAuthKeyExists without making any change if any of the given keys is
// already registered for the user (including duplicates within authKeys
// itself).
func (d *DB) AddUserAuthKeys(username string, authKeys []string) (*models.User, error) {
	existing, err := d.ListUserAuthKeys(username)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{}, len(existing))
	for _, k := range existing {
		seen[k] = struct{}{}
	}
	updated := existing
	for _, k := range authKeys {
		if _, ok := seen[k]; ok {
			return nil, fmt.Errorf("%w: %q", ErrAuthKeyExists, k)
		}
		seen[k] = struct{}{}
		updated = append(updated, k)
	}

	if err := d.SetUserAuthKeys(username, updated); err != nil {
		return nil, err
	}
	return d.FindUser(username, "")
}

// RemoveUserAuthKey removes the SSH public key at the given index, as
// returned by ListUserAuthKeys, and returns the updated user. It returns
// models.ErrInvalidParameters if the index is out of range.
func (d *DB) RemoveUserAuthKey(username string, index uint32) (*models.User, error) {
	existing, err := d.ListUserAuthKeys(username)
	if err != nil {
		return nil, err
	}
	if int(index) >= len(existing) {
		return nil, fmt.Errorf("%w: auth key index %d out of range", models.ErrInvalidParameters, index)
	}

	updated := make([]string, 0, len(existing)-1)
	updated = append(updated, existing[:index]...)
	updated = append(updated, existing[index+1:]...)

	if err := d.SetUserAuthKeys(username, updated); err != nil {
		return nil, err
	}
	return d.FindUser(username, "")
}
