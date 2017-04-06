package ext

// Match wildcard string
func WildMatch(pattern string, input string) bool {
	return wildcardTest(pattern, input, 0, 0)
}

func wildcardTest(pattern string, input string, spointer int, rpointer int) bool {
	if spointer == len(input) && rpointer == len(pattern) {
		return true
	} else if spointer >= len(input) || rpointer >= len(pattern) {
		return false
	} else {
		if pattern[rpointer] == '?' {
			return wildcardTest(pattern, input, spointer+1, rpointer+1)
		} else if pattern[rpointer] == '*' {
			return wildcardTest(pattern, input, spointer+1, rpointer) ||
				wildcardTest(pattern, input, spointer+1, rpointer+1) ||
				wildcardTest(pattern, input, spointer, rpointer+1)
		} else {
			if pattern[rpointer] == input[spointer] {
				return wildcardTest(pattern, input, spointer+1, rpointer+1)
			} else {
				return false
			}
		}
	}
}
