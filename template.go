package gf

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/goframework/gf/html/template"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var _FUNC_MAP = template.FuncMap{
	"json": tmplJson,
}

type cacheTemplate struct {
	ModTime  time.Time
	Template *template.Template
}

var mCacheTemplateLock = sync.Mutex{}
var mCacheTemplate = map[string]*cacheTemplate{}

func ParseTemplateFiles(templateFunc map[string]interface{}, filenames ...string) (*template.Template, error) {
	if len(filenames) > 0 {
		cacheKey := fmt.Sprint(templateFunc, filenames)
		for i := range filenames {
			filenames[i] = filepath.Join(mViewDir, filenames[i])
		}
		modTime, err := lastModTime(filenames)

		mCacheTemplateLock.Lock()
		tpl, ok := mCacheTemplate[cacheKey]
		mCacheTemplateLock.Unlock()

		if ok {
			if err != nil {
				return nil, err
			}
			if modTime.Equal(tpl.ModTime) {
				return tpl.Template, nil
			}
		}

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

		name := filepath.Base(filenames[0])

		temp, err := template.New(name).Funcs(funcMap).ParseFiles(filenames...)
		if err == nil {
			newCacheTemplate := &cacheTemplate{modTime, temp}
			mCacheTemplateLock.Lock()
			mCacheTemplate[cacheKey] = newCacheTemplate
			mCacheTemplateLock.Unlock()
		}

		return temp, err
	}

	return nil, errors.New("gf/html/template: no files named in call to ParseFiles")
}

func tmplJson(v interface{}) template.JS {
	a, _ := json.Marshal(v)
	return template.JS(a)
}

func lastModTime(files []string) (time.Time, error) {
	t := time.Time{}
	for _, f := range files {
		info, err := os.Stat(f)
		if err == nil {
			modTime := info.ModTime()
			if modTime.After(t) {
				t = modTime
			}
		} else {
			return t, err
		}
	}

	return t, nil
}
