package user

import (
	"reflect"
	"testing"
)

func TestDiffMembership(t *testing.T) {
	tests := []struct {
		name       string
		current    []string
		desired    []string
		wantAdd    []string
		wantRemove []string
	}{
		{
			name:    "no change",
			current: []string{"wheel", "docker"},
			desired: []string{"wheel", "docker"},
		},
		{
			name:       "add only",
			current:    []string{"wheel"},
			desired:    []string{"wheel", "docker"},
			wantAdd:    []string{"docker"},
			wantRemove: nil,
		},
		{
			name:       "remove only",
			current:    []string{"wheel", "docker"},
			desired:    []string{"wheel"},
			wantAdd:    nil,
			wantRemove: []string{"docker"},
		},
		{
			name:       "add and remove",
			current:    []string{"wheel", "docker"},
			desired:    []string{"docker", "sudo"},
			wantAdd:    []string{"sudo"},
			wantRemove: []string{"wheel"},
		},
		{
			name:       "empty current",
			current:    nil,
			desired:    []string{"wheel"},
			wantAdd:    []string{"wheel"},
			wantRemove: nil,
		},
		{
			name:       "empty desired removes everything",
			current:    []string{"wheel", "docker"},
			desired:    nil,
			wantAdd:    nil,
			wantRemove: []string{"wheel", "docker"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAdd, gotRemove := diffMembership(tt.current, tt.desired)
			if !reflect.DeepEqual(gotAdd, tt.wantAdd) {
				t.Errorf("toAdd = %v, want %v", gotAdd, tt.wantAdd)
			}
			if !reflect.DeepEqual(gotRemove, tt.wantRemove) {
				t.Errorf("toRemove = %v, want %v", gotRemove, tt.wantRemove)
			}
		})
	}
}
