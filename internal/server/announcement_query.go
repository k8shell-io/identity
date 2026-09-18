// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	queryv1 "github.com/k8shell-io/common/pkg/api/gen/go/query/v1"
	"github.com/k8shell-io/common/pkg/query"
)

// announcementsQueryDescriptor advertises which announcement fields are
// queryable/sortable via QueryAnnouncements (served as-is by
// GetAnnouncementsQuerySchema), and is reused to validate incoming queries
// so the two can never drift apart. Translations (per-language body) and
// read_count are deliberately left out — the former isn't a flat scalar
// column and the latter is a computed aggregate, neither of which the
// generic query engine filters/sorts on (the same reason OnboardRule's own
// descriptor excludes id: a dedicated Get-by-id RPC already covers that).
var announcementsQueryDescriptor = query.NewDescriptor("announcements").
	Field("name", queryv1.FieldType_FIELD_TYPE_STRING,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE).
	Field("createdBy", queryv1.FieldType_FIELD_TYPE_STRING,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE).
	Field("orgs", queryv1.FieldType_FIELD_TYPE_STRING,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE, queryv1.Operator_OPERATOR_IN).
	Field("roles", queryv1.FieldType_FIELD_TYPE_STRING,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE, queryv1.Operator_OPERATOR_IN).
	Field("active", queryv1.FieldType_FIELD_TYPE_BOOLEAN,
		queryv1.Operator_OPERATOR_EQ).
	Field("startsAt", queryv1.FieldType_FIELD_TYPE_DATETIME,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_GT, queryv1.Operator_OPERATOR_GTE,
		queryv1.Operator_OPERATOR_LT, queryv1.Operator_OPERATOR_LTE, queryv1.Operator_OPERATOR_EXISTS).
	Field("endsAt", queryv1.FieldType_FIELD_TYPE_DATETIME,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_GT, queryv1.Operator_OPERATOR_GTE,
		queryv1.Operator_OPERATOR_LT, queryv1.Operator_OPERATOR_LTE, queryv1.Operator_OPERATOR_EXISTS).
	Field("createdAt", queryv1.FieldType_FIELD_TYPE_DATETIME,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_GT, queryv1.Operator_OPERATOR_GTE,
		queryv1.Operator_OPERATOR_LT, queryv1.Operator_OPERATOR_LTE, queryv1.Operator_OPERATOR_EXISTS).
	Field("updatedAt", queryv1.FieldType_FIELD_TYPE_DATETIME,
		queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_GT, queryv1.Operator_OPERATOR_GTE,
		queryv1.Operator_OPERATOR_LT, queryv1.Operator_OPERATOR_LTE, queryv1.Operator_OPERATOR_EXISTS).
	DefaultSort("createdAt", queryv1.SortDir_SORT_DIR_DESC).
	Build()

// announcementsQueryFieldMap overrides how announcementsQueryDescriptor
// fields resolve to identity.announcements columns: differing column names
// (createdBy -> created_by, etc.) and marking orgs/roles as Postgres array
// columns.
var announcementsQueryFieldMap = query.FieldMap{
	"createdBy": {Name: "created_by"},
	"orgs":      {Array: true},
	"roles":     {Array: true},
	"startsAt":  {Name: "starts_at"},
	"endsAt":    {Name: "ends_at"},
	"createdAt": {Name: "created_at"},
	"updatedAt": {Name: "updated_at"},
}
