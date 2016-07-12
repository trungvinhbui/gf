package ext

import (
	"os"
	"regexp"
	"strings"
	"syscall"
	"path/filepath"
)

type VarType struct {
	Str string
}

func (v VarType) String() string {
	return v.Str
}

// Replace ${VAR|default} by environment variable VAR or using "default" value if VAR is not set.
func ReplaceEnv(s string) string {

	reg, _ := regexp.Compile("(\\${)([^}]*)(})")

	s = reg.ReplaceAllStringFunc(s, func(m string) string {
		key := m[2 : len(m)-1]
		defaultValue := ""
		if defaultId := strings.Index(key, "|"); defaultId > 0 {
			defaultValue = key[defaultId+1:]
			key = key[:defaultId]
		}
		value, found := syscall.Getenv(key)
		if !found {
			value = defaultValue
		}
		return value
	})

	return s
}

// Match variables string
// Example:
//            /path/to/{name}
//            /path/to/{name:pattern}
func VarMatch(pattern string, input string) (map[string]VarType, bool) {

	lenP := len(pattern)
	lenI := len(input)

	i := 0
	p := 0

	vars := map[string]VarType{}

	for i < lenI && p < lenP {
		if pattern[p] == '{' {
			pe := -1
			subPattern := pattern[p:]
			countBracket := 0
			for i := 0; i < len(subPattern); i++ {
				if subPattern[i] == '{' {
					countBracket++
				} else if subPattern[i] == '}' {
					countBracket--
					if countBracket == 0 {
						pe = i
						break
					}
				}
			}

			if pe <= 1 {
				return nil, false
			}
			varName := pattern[p+1 : p+pe]

			ie := strings.Index(input[i:], "/")
			if ie < 0 {
				ie = len(input[i:])
			}

			varVal := input[i : i+ie]

			iRegex := strings.Index(varName, ":")
			if iRegex >= 0 {
				varPattern := varName[iRegex+1:]
				varName = varName[:iRegex]

				if matched, _ := regexp.MatchString(varPattern, varVal); !matched {
					return nil, false
				}
			}

			vars[varName] = VarType{varVal}

			p = p + pe + 1
			i = i + ie

		} else {
			if pattern[p] != input[i] {
				return nil, false
			}
			p++
			i++
		}
	}

	if i < lenI || p < lenP {
		return nil, false
	}

	return vars, true
}

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

func FileExists(name string) bool {
	info, err := os.Stat(name)
	if os.IsNotExist(err) || info.IsDir() {
		return false
	}
	return true
}

func FolderExists(name string) bool {
	info, err := os.Stat(name)
	if os.IsNotExist(err) || !info.IsDir() {
		return false
	}
	return true
}

func FileNameFromPath(filePath string) string {
	return  filepath.Base(filePath)
}

func ArrayContains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
