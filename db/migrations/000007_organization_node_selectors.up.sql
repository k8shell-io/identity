-- node_selectors is the organization's desired Kubernetes nodeSelector for its
-- workspaces: label key -> single value. Desired state only; never counts or
-- readiness of matching nodes.
ALTER TABLE identity.organizations
    ADD COLUMN node_selectors jsonb NOT NULL DEFAULT '{}'::jsonb;
