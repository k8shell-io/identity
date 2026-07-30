// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	queryv1 "github.com/k8shell-io/common/pkg/api/gen/go/query/v1"
	"github.com/k8shell-io/common/pkg/query"
)

// onboardRulesQueryDescriptor advertises which onboard rule fields are
// queryable/sortable via QueryOnboardRules (served as-is by
// GetOnboardRulesQuerySchema), and is reused to validate incoming queries
// so the two can never drift apart. A frontend renders the pending
// approval queue by filtering status = "pending" (or action = "waitlist",
// equivalently) — there is no separate "list waitlist" schema/RPC.
var onboardRulesQueryDescriptor = query.NewDescriptor("onboardRules").
	Field("idp", queryv1.FieldType_FIELD_TYPE_STRING,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE).
	Field("usernamePattern", queryv1.FieldType_FIELD_TYPE_STRING,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE).
	Field("org", queryv1.FieldType_FIELD_TYPE_STRING,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE).
	Field("action", queryv1.FieldType_FIELD_TYPE_STRING,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE, queryv1.Operator_OPERATOR_IN).
	Field("status", queryv1.FieldType_FIELD_TYPE_STRING,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE, queryv1.Operator_OPERATOR_IN).
	Field("priority", queryv1.FieldType_FIELD_TYPE_NUMBER,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_GT, queryv1.Operator_OPERATOR_GTE,
		queryv1.Operator_OPERATOR_LT, queryv1.Operator_OPERATOR_LTE).
	Field("roles", queryv1.FieldType_FIELD_TYPE_STRING,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE, queryv1.Operator_OPERATOR_IN).
	Field("sudo", queryv1.FieldType_FIELD_TYPE_BOOLEAN,
		queryv1.Operator_OPERATOR_EQ).
	Field("fullname", queryv1.FieldType_FIELD_TYPE_STRING,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE).
	Field("email", queryv1.FieldType_FIELD_TYPE_STRING,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE).
	Field("requestedAt", queryv1.FieldType_FIELD_TYPE_DATETIME,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_GT, queryv1.Operator_OPERATOR_GTE,
		queryv1.Operator_OPERATOR_LT, queryv1.Operator_OPERATOR_LTE, queryv1.Operator_OPERATOR_EXISTS).
	Field("decidedAt", queryv1.FieldType_FIELD_TYPE_DATETIME,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_GT, queryv1.Operator_OPERATOR_GTE,
		queryv1.Operator_OPERATOR_LT, queryv1.Operator_OPERATOR_LTE, queryv1.Operator_OPERATOR_EXISTS).
	Field("createdAt", queryv1.FieldType_FIELD_TYPE_DATETIME,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_GT, queryv1.Operator_OPERATOR_GTE,
		queryv1.Operator_OPERATOR_LT, queryv1.Operator_OPERATOR_LTE, queryv1.Operator_OPERATOR_EXISTS).
	DefaultSort("priority", queryv1.SortDir_SORT_DIR_ASC).
	Build()

// onboardRulesQueryFieldMap overrides how onboardRulesQueryDescriptor
// fields resolve to identity.onboard_rules columns: differing column names
// (usernamePattern -> username_pattern, etc.) and marking roles as a
// Postgres array column.
var onboardRulesQueryFieldMap = query.FieldMap{
	"usernamePattern": {Name: "username_pattern"},
	"roles":           {Array: true},
	"requestedAt":     {Name: "requested_at"},
	"decidedAt":       {Name: "decided_at"},
	"createdAt":       {Name: "created_at"},
}
