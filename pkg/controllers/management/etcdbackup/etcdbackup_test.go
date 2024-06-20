package etcdbackup

import (
	"testing"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	rketypes "github.com/rancher/rke/types"
	"github.com/stretchr/testify/assert"
)

func Test_filterBackups(t *testing.T) {
	recurring := &v3.EtcdBackup{}
	manual := &v3.EtcdBackup{
		Spec: rketypes.EtcdBackupSpec{
			Manual: true,
		},
	}
	failed := &v3.EtcdBackup{}
	rketypes.BackupConditionCompleted.False(failed)
	completed := &v3.EtcdBackup{}
	rketypes.BackupConditionCompleted.True(completed)

	tests := []struct {
		name     string
		input    []*v3.EtcdBackup
		expected []*v3.EtcdBackup
		filters  []FilterFunc
	}{
		{
			name: "recurring",
			input: []*v3.EtcdBackup{
				manual, recurring,
			},
			expected: []*v3.EtcdBackup{
				recurring,
			},
			filters: []FilterFunc{
				IsBackupRecurring,
			},
		}, {
			name: "completed",
			input: []*v3.EtcdBackup{
				completed, failed,
			},
			expected: []*v3.EtcdBackup{
				completed,
			},
			filters: []FilterFunc{
				IsBackupCompleted,
			},
		}, {
			name: "failed",
			input: []*v3.EtcdBackup{
				completed, failed,
			},
			expected: []*v3.EtcdBackup{
				failed,
			},
			filters: []FilterFunc{
				IsBackupFailed,
			},
		}, {
			name: "recurring and completed",
			input: []*v3.EtcdBackup{
				recurring, manual, completed, failed,
			},
			expected: []*v3.EtcdBackup{
				completed,
			},
			filters: []FilterFunc{
				IsBackupRecurring, IsBackupCompleted,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, filterBackups(tt.input, tt.filters...))
		})
	}
}

func Test_sliceToMap(t *testing.T) {
	sliceTests := []struct {
		name     string
		elements []any
		want     map[string]any
	}{
		{
			name:     "single string pair",
			elements: []any{"test", "value"},
			want: map[string]any{
				"test": "value",
			},
		},
		{
			name:     "multiple elements",
			elements: []any{"test1", "value1", "test2", "value2"},
			want: map[string]any{
				"test1": "value1",
				"test2": "value2",
			},
		},
		{
			name:     "non-string value",
			elements: []any{"duration", time.Second * 10},
			want: map[string]any{
				"duration": time.Second * 10,
			},
		},
		{
			name:     "non-string key",
			elements: []any{time.Second * 10, 5},
			want: map[string]any{
				"10s": 5,
			},
		},
		{
			name:     "uneven number of elements",
			elements: []any{"test", "value", "hanging"},
			want: map[string]any{
				"test":    "value",
				"hanging": "",
			},
		},
	}

	for _, tt := range sliceTests {
		t.Run(tt.name, func(t *testing.T) {
			result := sliceToMap(tt.elements...)
			assert.Equal(t, tt.want, result)
		})
	}
}
