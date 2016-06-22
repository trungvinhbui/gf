package gf

import (
	"encoding/json"
	"fmt"
	"github.com/goframework/gf/html/template"
	"path/filepath"
)

var funcMap = template.FuncMap{
	"json": tmplJson,
}

func ParseTemplateFiles(filename... string) (*template.Template, error) {
	if len(filename) > 0 {
		name := filepath.Base(filename[0])
		return template.New(name).Funcs(funcMap).ParseFiles(filename...)
	}

	return nil, fmt.Errorf("html/template: no files named in call to ParseFiles")
}

func tmplJson(v interface{}) template.JS {
	a, _ := json.Marshal(v)
	return template.JS(a)
}

