package scanner

// All is the master list of every scanner, in the order they are offered to a
// user. Adding a scanner is a single line here.
var All = []Scanner{
	&PasswordSSH{},
	&AccessibleRDP{},
	&AccessibleDB{},
	&InsecureHTTP{},
}

// ByName maps each scanner name to its implementation.
var ByName = func() map[string]Scanner {
	m := make(map[string]Scanner, len(All))
	for _, s := range All {
		m[s.Name()] = s
	}
	return m
}()

// Defaults returns the scanners --all selects, in registration order.
func Defaults() []Scanner {
	var out []Scanner
	for _, s := range All {
		if s.DefaultEnabled() {
			out = append(out, s)
		}
	}
	return out
}
