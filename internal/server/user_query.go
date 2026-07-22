// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	queryv1 "github.com/k8shell-io/common/pkg/api/gen/go/query/v1"
	"github.com/k8shell-io/common/pkg/query"
)

// usersQueryDescriptor advertises which user fields are queryable/sortable
// via GetUsersRequest.query (served as-is by GetUsersQuerySchema), and is
// reused to validate incoming queries so the two can never drift apart.
//
// roles and blueprints are FIELD_TYPE_STRING like any other text field —
// they're Postgres character varying[] columns underneath, but that's a
// storage detail expressed only in usersQueryFieldMap (Array: true), which
// changes eq/ne/in to array-membership/overlap operators. The client-facing
// schema doesn't need to know the column shape.
var usersQueryDescriptor = query.NewDescriptor("users").
	Field("username", queryv1.FieldType_FIELD_TYPE_STRING,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE).
	Field("email", queryv1.FieldType_FIELD_TYPE_STRING,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE).
	Field("org", queryv1.FieldType_FIELD_TYPE_STRING,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE).
	Field("roles", queryv1.FieldType_FIELD_TYPE_STRING,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE, queryv1.Operator_OPERATOR_IN).
	Field("blueprints", queryv1.FieldType_FIELD_TYPE_STRING,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE, queryv1.Operator_OPERATOR_IN).
	Field("sudo", queryv1.FieldType_FIELD_TYPE_BOOLEAN,
		queryv1.Operator_OPERATOR_EQ).
	Field("source", queryv1.FieldType_FIELD_TYPE_STRING,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE).
	Field("isValid", queryv1.FieldType_FIELD_TYPE_BOOLEAN,
		queryv1.Operator_OPERATOR_EQ).
	Field("locked", queryv1.FieldType_FIELD_TYPE_BOOLEAN,
		queryv1.Operator_OPERATOR_EQ).
	Field("expiresAt", queryv1.FieldType_FIELD_TYPE_DATETIME,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_GT, queryv1.Operator_OPERATOR_GTE,
		queryv1.Operator_OPERATOR_LT, queryv1.Operator_OPERATOR_LTE, queryv1.Operator_OPERATOR_EXISTS).
	DefaultSort("username", queryv1.SortDir_SORT_DIR_ASC).
	Build()

// usersQueryFieldMap overrides how usersQueryDescriptor fields resolve to
// identity.users columns: a differing column name (org -> organization),
// and/or marking a field as a Postgres array column (roles, blueprints).
var usersQueryFieldMap = query.FieldMap{
	"org":        {Name: "organization"},
	"isValid":    {Name: "is_valid"},
	"expiresAt":  {Name: "expires_at"},
	"roles":      {Array: true},
	"blueprints": {Array: true},
}
