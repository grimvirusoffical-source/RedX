package rsx

// Random fills b from the operating system's entropy source (getrandom on Linux).
func Random(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if err := osRandom(b); err != nil {
		return ErrRNG
	}
	return nil
}

func mustRandom(b []byte) error { return Random(b) }
