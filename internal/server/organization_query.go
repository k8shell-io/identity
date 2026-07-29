// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	queryv1 "github.com/k8shell-io/common/pkg/api/gen/go/query/v1"
	"github.com/k8shell-io/common/pkg/query"
	backend "github.com/k8shell-io/identity/internal/db"
)

// organizationsQueryDescriptor advertises which organization fields are
// queryable/sortable via QueryOrganizations (served as-is by
// GetOrganizationsQuerySchema), and is reused to validate incoming queries
// so the two can never drift apart. name/description/createdAt are
// identity.organizations' own columns; userCount and adminUsernames are
// joined/computed by ListOrganizations/ListOrganizationsQuery — since
// userCount is a COUNT() aggregate, ListOrganizationsQuery applies every
// condition (not just userCount's) as a HAVING rather than a WHERE clause,
// which is valid here because every non-aggregate field is also a GROUP BY
// key. adminUsernames is FIELD_TYPE_STRING like roles/blueprints on the
// users resource — the array-ness is a storage detail expressed only in
// organizationsQueryFieldMap (Array: true), which changes eq/ne/in to
// array-membership/overlap operators.
var organizationsQueryDescriptor = query.NewDescriptor("organizations").
	Field("name", queryv1.FieldType_FIELD_TYPE_STRING,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE).
	Field("description", queryv1.FieldType_FIELD_TYPE_STRING,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE).
	Field("createdAt", queryv1.FieldType_FIELD_TYPE_DATETIME,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_GT, queryv1.Operator_OPERATOR_GTE,
		queryv1.Operator_OPERATOR_LT, queryv1.Operator_OPERATOR_LTE, queryv1.Operator_OPERATOR_EXISTS).
	Field("userCount", queryv1.FieldType_FIELD_TYPE_NUMBER,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE, queryv1.Operator_OPERATOR_GT,
		queryv1.Operator_OPERATOR_GTE, queryv1.Operator_OPERATOR_LT, queryv1.Operator_OPERATOR_LTE).
	Field("adminUsernames", queryv1.FieldType_FIELD_TYPE_STRING,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE, queryv1.Operator_OPERATOR_IN).
	DefaultSort("name", queryv1.SortDir_SORT_DIR_ASC).
	Build()

// organizationsQueryFieldMap overrides how organizationsQueryDescriptor
// fields resolve to SQL, qualified with the "o"/"u" aliases used by
// ListOrganizations/ListOrganizationsQuery. userCount maps to the same
// COUNT(u.username) expression, and adminUsernames to the same
// backend.OrganizationAdminUsernamesExpr correlated subquery, as
// ListOrganizations' own SELECT list, so a condition and the value it's
// compared against always agree.
var organizationsQueryFieldMap = query.FieldMap{
	"name":           {Name: "o.name"},
	"description":    {Name: "o.description"},
	"createdAt":      {Name: "o.created_at"},
	"userCount":      {Name: "COUNT(u.username)"},
	"adminUsernames": {Name: backend.OrganizationAdminUsernamesExpr, Array: true},
}
