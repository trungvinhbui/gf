package ext

import (
	"os"
	"regexp"
	"strings"
	"syscall"
)

// Replace ${VAR|default} by environment variable VAR or using "default" value if VAR is not set.
func ReplaceEnv(s string) string {

	reg, _ := regexp.Compile(`(\$\{)([^}]*)(})`)

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

func ArrayContains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
