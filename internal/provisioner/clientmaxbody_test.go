package provisioner

import (
	"strings"
	"testing"
)

// The plan's request-body ceiling is rendered by the panel from its own column,
// not carried inside the customer's directive block. It used to live in
// nginx_settings.extra_directives, which the nginx-settings route replaces
// wholesale with the customer's own text.
func TestThePlanCeilingIsRenderedOnBothServerBlocks(t *testing.T) {
	for _, tc := range []struct {
		name string
		tls  bool
	}{
		{name: "plain HTTP"},
		{name: "HTTPS", tls: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := baseOpts()
			opts.ClientMaxBody = "8192m"
			if tc.tls {
				opts.CertPath, opts.KeyPath = "/etc/ssl/x.pem", "/etc/ssl/x.key"
			}

			config := renderVhost(t, opts)

			if got := strings.Count(config, "client_max_body_size 8192m;"); got != 1 {
				t.Fatalf("the vhost states the ceiling %d times, want exactly 1:\n%s", got, config)
			}
		})
	}
}

// A plan that states no ceiling must leave the directive out entirely. An empty
// one is a config nginx refuses to load, which would take the whole host down on
// the next reload rather than one domain.
func TestNoPlanCeilingRendersNoDirective(t *testing.T) {
	config := renderVhost(t, baseOpts())

	if strings.Contains(config, "client_max_body_size") {
		t.Fatalf("a vhost with no plan ceiling still states the directive:\n%s", config)
	}
}

// The ceiling belongs to the panel's own block, above the customer's. Rendering
// it inside ExtraDirectives is what let the customer replace it.
func TestThePlanCeilingIsRenderedOutsideTheCustomerBlock(t *testing.T) {
	opts := baseOpts()
	opts.ClientMaxBody = "8192m"
	opts.ExtraDirectives = "add_header X-Test safe;"

	config := renderVhost(t, opts)

	ceiling := strings.Index(config, "client_max_body_size 8192m;")
	customer := strings.Index(config, "# ---- Additional directives (user-provided) ----")
	if ceiling < 0 || customer < 0 {
		t.Fatalf("one of the two blocks is missing (ceiling=%d, customer=%d):\n%s", ceiling, customer, config)
	}
	if ceiling > customer {
		t.Fatal("the plan ceiling is rendered inside or after the customer's own block")
	}
}
