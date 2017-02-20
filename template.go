package gf

import (
	"encoding/json"
	"fmt"
	"github.com/goframework/gf/html/template"
	"path/filepath"
)

var _FUNC_MAP = template.FuncMap{
	"json": tmplJson,
}

func ParseTemplateFiles(templateFunc map[string]interface{}, filename... string) (*template.Template, error) {
	if len(filename) > 0 {
		var funcMap template.FuncMap
		if len(templateFunc) > 0 {
			funcMap = template.FuncMap{}
			for name, fc := range _FUNC_MAP {
				funcMap[name] = fc
			}
			for name, fc := range templateFunc {
				funcMap[name] = fc
			}
		} else {
			funcMap = _FUNC_MAP
		}

		name := filepath.Base(filename[0])
		return template.New(name).Funcs(funcMap).ParseFiles(filename...)
	}

	return nil, fmt.Errorf("html/template: no files named in call to ParseFiles")
}

func tmplJson(v interface{}) template.JS {
	a, _ := json.Marshal(v)
	return template.JS(a)
}

