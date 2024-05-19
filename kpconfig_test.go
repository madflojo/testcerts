package testcerts

import (
	"testing"
)

type KPConfigTestCase struct {
	name string
	cfg  KeyPairConfig
	err  error
}

func TestKPConfigs(t *testing.T) {
	tc := []KPConfigTestCase{
		{
			name: "Happy Path - Simple Domain",
			cfg: KeyPairConfig{
				Domains: []string{"example.com"},
			},
			err: nil,
		},
		{
			name: "Happy Path - Multiple Domains",
			cfg: KeyPairConfig{
				Domains: []string{"example.com", "example.org"},
			},
			err: nil,
		},
		{
			name: "Happy Path - Multiple Domains with Wildcard",
			cfg: KeyPairConfig{
				Domains: []string{"example.com", "*.example.com"},
			},
			err: nil,
		},
		{
			name: "Empty Config",
			cfg:  KeyPairConfig{},
			err:  ErrEmptyConfig,
		},
		{
			name: "Happy Path - Valid IP",
			cfg: KeyPairConfig{
				IPAddresses: []string{"127.0.0.1"},
			},
			err: nil,
		},
		{
			name: "Happy Path - Multiple Valid IPs",
			cfg: KeyPairConfig{
				IPAddresses: []string{"127.0.0.1", "10.0.0.0"},
			},
			err: nil,
		},
		{
			name: "Happy Path - IPv6 Localhost",
			cfg: KeyPairConfig{
				IPAddresses: []string{"::1"},
			},
			err: nil,
		},
		{
			name: "Happy Path - Multiple IPv6 Addresses",
			cfg: KeyPairConfig{
				IPAddresses: []string{"::1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
			},
			err: nil,
		},
		{
			name: "Happy Path - Valid IP and Domain",
			cfg: KeyPairConfig{
				IPAddresses: []string{"127.0.0.1", "10.0.0.0"},
				Domains:     []string{"example.com", "localhost"},
			},
			err: nil,
		},
		{
			name: "Invalid IP",
			cfg: KeyPairConfig{
				IPAddresses: []string{"127.0.0.1", "not an IP"},
			},
			err: ErrInvalidIP,
		},
	}

	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			if err != c.err {
				t.Errorf("Validation failed, expected error return of %v, got %v", c.err, err)
			}
		})
	}
}

func TestKPIPAddresses(t *testing.T) {
	tc := []KPConfigTestCase{
		{
			name: "Happy Path - Valid IP",
			cfg: KeyPairConfig{
				IPAddresses: []string{"127.0.0.1"},
			},
			err: nil,
		},
		{
			name: "Happy Path - Multiple Valid IPs",
			cfg: KeyPairConfig{
				IPAddresses: []string{"127.0.0.1", "10.0.0.0"},
			},
			err: nil,
		},
		{
			name: "Happy Path - IPv6 Localhost",
			cfg: KeyPairConfig{
				IPAddresses: []string{"::1"},
			},
			err: nil,
		},
		{
			name: "Happy Path - Multiple IPv6 Addresses",
			cfg: KeyPairConfig{
				IPAddresses: []string{"::1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
			},
			err: nil,
		},
		{
			name: "Happy Path - Valid IP and Domain",
			cfg: KeyPairConfig{
				IPAddresses: []string{"127.0.0.1", "10.0.0.0"},
				Domains:     []string{"example.com", "localhost"},
			},
			err: nil,
		},
		{
			name: "Invalid IP",
			cfg: KeyPairConfig{
				IPAddresses: []string{"127.0.0.1", "not an IP"},
			},
			err: ErrInvalidIP,
		},
	}

	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			ips, err := c.cfg.IPNetAddresses()
			if err != c.err {
				t.Fatalf("IPAddresses failed, expected error return of %v, got %v", c.err, err)
			}
			if err == nil {
				if len(ips) != len(c.cfg.IPAddresses) {
					t.Errorf("IPAddresses failed, expected %d IP addresses, got %d", len(ips), len(c.cfg.IPAddresses))
				}
			}
		})
	}
}
