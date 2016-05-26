package gf

import "strings"
import "html"

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
		for key, value := range values {
			values[key] = html.EscapeString(value)
		}
		return values
	}
	return nil
}

func (this *Form) ArrayNoEscape(key string) []string {
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
			return html.EscapeString(strings.Join(values, ","))
		}
	}
	return ""
}

func (this *Form) StringNoEscape(key string) string {
	values, ok := this.formMap[key]
	if ok {
		if len(values) >= 1 {
			return strings.Join(values, ",")
		}
	}
	return ""
}
