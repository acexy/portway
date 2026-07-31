// Package limits defines compiled resource boundaries shared across layers.
package limits

const (
	// HardMaxProxiesPerClient bounds every client proxy set in all modes.
	HardMaxProxiesPerClient = 128
	// HardMaxActiveLinksPerClient bounds active links owned by one client.
	HardMaxActiveLinksPerClient = 512
)
