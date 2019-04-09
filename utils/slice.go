package utils

func Contains(sl []interface{}, v interface{}) bool {
	for _, vv := range sl {
		if vv == v {
			return true
		}
	}
	return false
}

// Returns true is sl contains v
func ContainsString(sl []string, v string) bool {
	for _, vv := range sl {
		if vv == v {
			return true
		}
	}
	return false
}

// Returns true if sl contains all values of other
func ContainsAll(sl []string, other []string) bool {
	for _, vo := range other {
		if !ContainsString(sl, vo) {
			return false
		}
	}

	return true
}