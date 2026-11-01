package policy

import "net/netip"

// ZeroAddr returns the zero netip.Addr (used in tests for name-only matching).
func ZeroAddr() netip.Addr { return netip.Addr{} }

// ParseTestAddr parses an IP address string for use in tests.
// ParseTestAddr panics if the string is not a valid IP.
func ParseTestAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic("ParseTestAddr: " + err.Error())
	}
	return a
}

