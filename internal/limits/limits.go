// Package limits defines compiled resource boundaries shared across layers.
package limits

const (
	// HardMaxBindingsPerClient bounds each client-owned Proxy or Forward set.
	HardMaxBindingsPerClient = 128
	// HardMaxActiveLinksPerClient bounds active links owned by one client.
	HardMaxActiveLinksPerClient = 512
)
