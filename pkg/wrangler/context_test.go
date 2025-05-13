package wrangler

import "testing"

func TestRateLimiting(t *testing.T) {
	rlTests := map[string]struct {
		qps   string
		burst string

		wantQPS   float32
		wantBurst int
	}{
		"not providing any settings": {
			wantQPS:   defaultQPS,
			wantBurst: defaultBurst,
		},
		"providing burst and qps": {
			qps:       "250",
			burst:     "90",
			wantQPS:   250,
			wantBurst: 90,
		},
		"providing qps": {
			qps:       "250",
			wantQPS:   250,
			wantBurst: defaultBurst,
		},
		"providing burst": {
			burst:     "90",
			wantQPS:   defaultQPS,
			wantBurst: 90,
		},
	}

	for name, tt := range rlTests {
		t.Run(name, func(t *testing.T) {
			if tt.qps != "" {
				t.Setenv("RANCHER_CLIENT_QPS", tt.qps)
			}
			if tt.burst != "" {
				t.Setenv("RANCHER_CLIENT_BURST", tt.burst)
			}

			qps, burst, err := clientRateLimiting()
			if err != nil {
				t.Fatal(err)
			}

			if qps != tt.wantQPS {
				t.Errorf("clientRateLimiting() qps got %v, want %v", qps, tt.wantQPS)
			}

			if burst != tt.wantBurst {
				t.Errorf("clientRateLimiting() burst got %v, want %v", burst, tt.wantBurst)
			}
		})
	}
}

func TestRateLimitingErrors(t *testing.T) {
	rlTests := map[string]struct {
		qps   string
		burst string

		wantQPS   float32
		wantBurst int
		wantErr   string
	}{
		"invalid burst": {
			qps:       "300",
			burst:     "bad value",
			wantQPS:   defaultQPS,
			wantBurst: defaultBurst,
			wantErr:   `parsing RANCHER_CLIENT_BURST: strconv.Atoi: parsing "bad value": invalid syntax`,
		},
		"invalid qps": {
			burst:     "300",
			qps:       "bad value",
			wantQPS:   defaultQPS,
			wantBurst: defaultBurst,
			wantErr:   `parsing RANCHER_CLIENT_QPS: strconv.ParseFloat: parsing "bad value": invalid syntax`,
		},
	}

	for name, tt := range rlTests {
		t.Run(name, func(t *testing.T) {
			if tt.qps != "" {
				t.Setenv("RANCHER_CLIENT_QPS", tt.qps)
			}
			if tt.burst != "" {
				t.Setenv("RANCHER_CLIENT_BURST", tt.burst)
			}

			qps, burst, err := clientRateLimiting()
			if err.Error() != tt.wantErr {
				t.Errorf("clientRateLimiting() got error %v, want %v", err, tt.wantErr)
			}

			if qps != tt.wantQPS {
				t.Errorf("clientRateLimiting() qps got %v, want %v", qps, tt.wantQPS)
			}

			if burst != tt.wantBurst {
				t.Errorf("clientRateLimiting() burst got %v, want %v", burst, tt.wantBurst)
			}
		})
	}

}
