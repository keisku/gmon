package ebpf

import (
	"testing"

	"github.com/go-delve/delve/pkg/proc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func Test_stackLabels(t *testing.T) {
	type args struct {
		stack []*proc.Function
	}
	tests := []struct {
		name string
		args args
		want prometheus.Labels
	}{
		{
			name: "stack length is 5",
			args: args{
				stack: []*proc.Function{
					{Name: "func1"},
					{Name: "func2"},
					{Name: "func3"},
					{Name: "func4"},
					{Name: "func5"},
				},
			},
			want: prometheus.Labels{
				"stack_0": "func5",
				"stack_1": "func4",
				"stack_2": "func3",
				"stack_3": "func2",
				"stack_4": "func1",
			},
		},
		{
			name: "stack length is 3",
			args: args{
				stack: []*proc.Function{
					{Name: "func1"},
					{Name: "func2"},
					{Name: "func3"},
				},
			},
			want: prometheus.Labels{
				"stack_0": "func3",
				"stack_1": "func2",
				"stack_2": "func1",
				"stack_3": "none",
				"stack_4": "none",
			},
		},
		{
			name: "stack length is 10",
			args: args{
				stack: []*proc.Function{
					{Name: "func1"},
					{Name: "func2"},
					{Name: "func3"},
					{Name: "func4"},
					{Name: "func5"},
					{Name: "func6"},
					{Name: "func7"},
					{Name: "func8"},
					{Name: "func9"},
					{Name: "func10"},
				},
			},
			want: prometheus.Labels{
				"stack_0": "func10",
				"stack_1": "func9",
				"stack_2": "func8",
				"stack_3": "func7",
				"stack_4": "func6",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, stackLabels(tt.args.stack))
		})
	}
}
