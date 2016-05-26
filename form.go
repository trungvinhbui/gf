package gf

import "strings"

type Form struct {
	formMap map[string][]string
}

func (this *Form) Exist(key string) bool {
	_, ok := this.formMap[key]
	return ok
}

func (this *Form) IsArray(key string) bool {
	values, ok := this.formMap[key]
	if ok {
		return len(values) > 1
	}
	return false
}

func (this *Form) Array(key string) []string {
	values, ok := this.formMap[key]
	if ok {
		return values
	}
	return nil
}

func (this *Form) String(key string) string {
	values, ok := this.formMap[key]
	if ok {
		if len(values) >= 1 {
			return strings.Join(values, ",")
		}
	}
	return ""
}
