package wrangler

import "testing"

func TestRateLimiting(t *testing.T) {
	rlTests := map[string]struct {
		env map[string]string

		wantQPS    float32
		wantBurst  int
		wantShared bool
	}{
		"not providing any settings": {
			wantQPS:   defaultQPS,
			wantBurst: defaultBurst,
		},
		"providing burst and qps": {
			env: map[string]string{
				"RANCHER_CLIENT_QPS":   "250",
				"RANCHER_CLIENT_BURST": "90",
			},
			wantQPS:   250,
			wantBurst: 90,
		},
		"providing qps": {
			env: map[string]string{
				"RANCHER_CLIENT_QPS": "250",
			},
			wantQPS:   250,
			wantBurst: defaultBurst,
		},
		"providing burst": {
			env: map[string]string{
				"RANCHER_CLIENT_BURST": "90",
			},
			wantQPS:   defaultQPS,
			wantBurst: 90,
		},
		"providing shared qps var": {
			env: map[string]string{
				"RANCHER_CLIENT_SHARED_RATELIMIT": "true",
			},
			wantQPS:    defaultQPS,
			wantBurst:  defaultBurst,
			wantShared: true,
		},
	}

	for name, tt := range rlTests {
		t.Run(name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			rl, err := clientRateLimiting()
			if err != nil {
				t.Fatal(err)
			}

			if rl.qps != tt.wantQPS {
				t.Errorf("clientRateLimiting() qps got %v, want %v", rl.qps, tt.wantQPS)
			}

			if rl.burst != tt.wantBurst {
				t.Errorf("clientRateLimiting() burst got %v, want %v", rl.burst, tt.wantBurst)
			}
			if rl.shared != tt.wantShared {
				t.Errorf("clientRateLimiting() shared got %v, want %v", rl.shared, tt.wantShared)
			}
		})
	}
}

func TestRateLimitingErrors(t *testing.T) {
	rlTests := map[string]struct {
		env map[string]string

		wantQPS   float32
		wantBurst int
		wantErr   string
	}{
		"invalid burst": {
			env: map[string]string{
				"RANCHER_CLIENT_BURST": "bad value",
				"RANCHER_CLIENT_QPS":   "300",
			},
			wantQPS:   300,
			wantBurst: defaultBurst,
			wantErr:   `parsing RANCHER_CLIENT_BURST: strconv.Atoi: parsing "bad value": invalid syntax`,
		},
		"invalid qps": {
			env: map[string]string{
				"RANCHER_CLIENT_BURST": "300",
				"RANCHER_CLIENT_QPS":   "bad value",
			},
			wantQPS:   defaultQPS,
			wantBurst: defaultBurst,
			wantErr:   `parsing RANCHER_CLIENT_QPS: strconv.ParseFloat: parsing "bad value": invalid syntax`,
		},
		"invalid shared configuration": {
			env: map[string]string{
				"RANCHER_CLIENT_SHARED_RATELIMIT": "bad value",
			},
			wantQPS:   defaultQPS,
			wantBurst: defaultBurst,
			wantErr:   `parsing RANCHER_CLIENT_SHARED_RATELIMIT: strconv.ParseBool: parsing "bad value": invalid syntax`,
		},
	}

	for name, tt := range rlTests {
		t.Run(name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			rl, err := clientRateLimiting()
			if err.Error() != tt.wantErr {
				t.Errorf("clientRateLimiting() got error %v, want %v", err, tt.wantErr)
			}

			if rl.qps != tt.wantQPS {
				t.Errorf("clientRateLimiting() qps got %v, want %v", rl.qps, tt.wantQPS)
			}

			if rl.burst != tt.wantBurst {
				t.Errorf("clientRateLimiting() burst got %v, want %v", rl.burst, tt.wantBurst)
			}
		})
	}

}
