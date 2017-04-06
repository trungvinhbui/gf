package gf

import (
	"fmt"
	"github.com/goframework/gf/ext"
	"regexp"
	"strings"
)

const (
	_PATH_SPLIT = "/"
	_VAR_SPLIT  = ":"
	_VAR_PRE    = "{"
	_VAR_SUF    = "}"
	_REGEX_PRE  = "^"
	_REGEX_SUF  = "$"
	_REGEX_ANY  = "^.*$"

	MAX_URL_PATH_LENGTH    = 2048
	MAX_HTTP_METHOD_LENGTH = 7 //method OPTIONS
)

type rootRouter struct {
	methodRouter *router
}

type router struct {
	handleFunc      func(*Context)
	regex           *regexp.Regexp
	varName         string
	subRawRouters   map[string]*router
	subRegexRouters map[string]*router
}

type pathPart struct {
	text     string
	isRegex  bool
	varName  string
	regex    *regexp.Regexp
	subPart  *pathPart
	fullPath string
}

func (r *rootRouter) Add(method string, path string, handler func(*Context)) error {
	if len(path) > MAX_URL_PATH_LENGTH {
		return fmt.Errorf("The path [%v] is over MAX_URL_PATH_LENGTH(%d)", path, MAX_URL_PATH_LENGTH)
	}
	path = strings.TrimRight(path, _PATH_SPLIT)
	partRoot, err := parsePath(path)
	if err != nil {
		return err
	}
	if r.methodRouter == nil {
		r.methodRouter = &router{}
		r.methodRouter.subRawRouters = map[string]*router{}
	}
	if r.methodRouter.subRawRouters[method] == nil {
		r.methodRouter.subRawRouters[method] = &router{}
	}

	return r.methodRouter.subRawRouters[method].add(partRoot, handler)
}

func (r *rootRouter) Route(method string, path string) (func(*Context), map[string]ext.Var) {
	if len(method) > MAX_HTTP_METHOD_LENGTH || len(path) > MAX_URL_PATH_LENGTH {
		return nil, nil
	}
	path = strings.TrimRight(path, _PATH_SPLIT)
	if r.methodRouter != nil && r.methodRouter.subRawRouters != nil {
		if methodRouter := r.methodRouter.subRawRouters[method]; methodRouter != nil {
			return methodRouter.route(path)
		}
	}
	return nil, nil
}

func (r *router) add(part *pathPart, handler func(*Context)) error {
	if part.subPart == nil {
		if r.handleFunc != nil {
			return fmt.Errorf("Double handler on same path [%v]", part.fullPath)
		} else if handler == nil {
			return fmt.Errorf("Handler is nil [%v]", part.fullPath)
		} else {
			r.handleFunc = handler
			return nil
		}
	} else {
		if part.subPart.isRegex {
			if r.subRegexRouters == nil {
				r.subRegexRouters = map[string]*router{}
			}

			if r.subRegexRouters[part.subPart.text] == nil {
				r.subRegexRouters[part.subPart.text] = &router{
					regex:   part.subPart.regex,
					varName: part.subPart.varName,
				}
			}

			return r.subRegexRouters[part.subPart.text].add(part.subPart, handler)
		} else {
			if r.subRawRouters == nil {
				r.subRawRouters = map[string]*router{}
			}

			if r.subRawRouters[part.subPart.text] == nil {
				r.subRawRouters[part.subPart.text] = &router{}
			}

			return r.subRawRouters[part.subPart.text].add(part.subPart, handler)
		}
	}
}

func (r *router) route(path string) (func(*Context), map[string]ext.Var) {
	parts := strings.SplitN(path, _PATH_SPLIT, 2)
	//thisPart := parts[0]
	var subPart string
	var haveSubPart bool
	if len(parts) == 2 {
		haveSubPart = true
		subPart = parts[1]
	} else {
		haveSubPart = false
	}

	if !haveSubPart {
		return r.handleFunc, nil
	}

	if haveSubPart {
		subPart0 := strings.SplitN(subPart, _PATH_SPLIT, 2)[0]
		if r.subRawRouters != nil {
			if subRouter := r.subRawRouters[subPart0]; subRouter != nil {
				h, v := subRouter.route(subPart)
				if h != nil {
					return h, v
				}
			}
		}
		if r.subRegexRouters != nil {
			for _, subRegexRouter := range r.subRegexRouters {
				if subRegexRouter.regex.MatchString(subPart0) {
					h, m := subRegexRouter.route(subPart)
					if h != nil {
						routerVar := map[string]ext.Var{subRegexRouter.varName: ext.Var(subPart0)}
						for k, v := range m {
							routerVar[k] = v
						}
						return h, routerVar
					}
				}
			}
		}
	}

	return nil, nil
}

func parsePath(path string) (*pathPart, error) {
	var partRoot *pathPart
	var pPart *pathPart

	strParts := strings.Split(path, _PATH_SPLIT)

	fullPath := ""
	for _, p := range strParts {
		if len(fullPath) > 0 {
			fullPath = fullPath + _PATH_SPLIT + p
		} else {
			fullPath = p
		}

		part := pathPart{text: p, subPart: nil, fullPath: fullPath, isRegex: false}

		if strings.HasPrefix(p, _VAR_PRE) && strings.HasSuffix(p, _VAR_SUF) {
			p = p[1 : len(p)-1]
			namePattern := strings.SplitN(p, _VAR_SPLIT, 2)
			name := namePattern[0]
			var pattern string
			if len(namePattern) == 2 {
				pattern = namePattern[1]
			} else {
				pattern = _REGEX_ANY
			}
			if !strings.HasPrefix(pattern, _REGEX_PRE) && !strings.HasSuffix(pattern, _REGEX_SUF) {
				pattern = _REGEX_PRE + pattern + _REGEX_SUF
			}
			regex, err := regexp.Compile(pattern)
			if err != nil {
				return nil, err
			}
			part.isRegex = true
			part.varName = name
			part.regex = regex
		}

		if partRoot == nil {
			partRoot = &part
		} else {
			pPart.subPart = &part
		}
		pPart = &part
	}
	return partRoot, nil
}
