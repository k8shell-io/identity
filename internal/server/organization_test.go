// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import "testing"

func TestValidateNodeSelectors(t *testing.T) {
	tests := []struct {
		name    string
		sel     map[string]string
		wantErr bool
	}{
		{"nil", nil, false},
		{"valid", map[string]string{"k8shell.io/pool": "gpu", "disktype": "ssd"}, false},
		{"multi value", map[string]string{"pool": "gpu,highmem"}, false},
		{"empty segment", map[string]string{"pool": "gpu,,highmem"}, true},
		{"trailing comma", map[string]string{"pool": "gpu,"}, true},
		{"bad segment", map[string]string{"pool": "gpu,not valid!"}, true},
		{"empty value", map[string]string{"disktype": ""}, false},
		{"empty key", map[string]string{"": "x"}, true},
		{"bad key", map[string]string{"bad key": "x"}, true},
		{"bad value", map[string]string{"disktype": "not valid!"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateNodeSelectors(tt.sel); (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
