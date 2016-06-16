package gf

import (
	"database/sql"
	"fmt"
	"github.com/goframework/gf/cfg"
	"github.com/goframework/gf/ext"
	"github.com/goframework/gf/sessions"
	"io"
	"net/http"
	"time"
)

const MAX_MULTIPART_MEMORY = 1024 * 1024 * 32

type Context struct {
	w              http.ResponseWriter
	r              *http.Request
	vars           map[string]interface{}
	isSelfResponse bool

	Config         *cfg.Cfg
	RouteVars      map[string]ext.VarType
	FinishFilter   bool
	RedirectPath   string
	RedirectStatus int
	Session        *sessions.Session
	ViewBases      []string
	View           string
	ViewData       map[string]interface{}
	JsonResponse   interface{}
	UrlPath        string
	Method         string
	IsGetMethod    bool
	IsPostMethod   bool
	IsUsingTSL     bool
	Form           Form
	Host           string

	DB *sql.DB
}

func (ctx *Context) Redirect(path string) {
	ctx.RedirectPath = path
	ctx.RedirectStatus = http.StatusFound
}

func (ctx *Context) RedirectPermanently(path string) {
	ctx.RedirectPath = path
	ctx.RedirectStatus = http.StatusMovedPermanently
}

func (ctx *Context) Set(key string, value interface{}) {
	ctx.vars[key] = value
}

func (ctx *Context) Get(key string) (interface{}, bool) {
	val, ok := ctx.vars[key]
	return val, ok
}

func (ctx *Context) GetString(key string) (string, bool) {
	val, ok := ctx.vars[key]
	if ok {
		str, ok := val.(string)
		return str, ok
	}
	return "", false
}

func (ctx *Context) GetInt(key string) (int, bool) {
	val, ok := ctx.vars[key]
	if ok {
		intval, ok := val.(int)
		return intval, ok
	}
	return 0, false
}

func (ctx *Context) GetBool(key string) (bool, bool) {
	val, ok := ctx.vars[key]
	if ok {
		boolval, ok := val.(bool)
		return boolval, ok
	}
	return false, false
}

func (ctx *Context) Write(data []byte) (int, error) {
	ctx.isSelfResponse = true
	return ctx.w.Write(data)
}

func (ctx *Context) WriteS(output string) {
	ctx.isSelfResponse = true
	fmt.Fprint(ctx.w, output)
}

func (ctx *Context) Writef(format string, content ...interface{}) {
	ctx.isSelfResponse = true
	fmt.Fprintf(ctx.w, format, content...)
}

func (ctx *Context) ClearSession() {
	for k := range ctx.Session.Values {
		delete(ctx.Session.Values, k)
	}
}

func (ctx *Context) NewSession() {
	ctx.ClearSession()

	var err error
	ctx.Session, err = mSessionStore.New(ctx.r, SERVER_SESSION_ID)
	if err != nil {
		http.Error(ctx.w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (ctx *Context) SetSessionFlash(key string, value interface{}) {
	ctx.Session.AddFlash(value, key)
}

func (ctx *Context) GetSessionFlash(key string) interface{} {
	vars := ctx.Session.Flashes(key)
	if len(vars) > 0 {
		return vars[0]
	}
	return nil
}


func (ctx *Context) GetResponseWriter() http.ResponseWriter {
	return ctx.w
}

func (ctx *Context) AddResponseHeader(key string, value string) {
	ctx.w.Header().Add(key, value)
}

// Set temporary cookie
func (ctx *Context) SetCookie(key string, value string) {
	cookie := http.Cookie{Name: key, Value: value}
	http.SetCookie(ctx.w, &cookie)
}

// Get cookie
func (ctx *Context) GetCookie(key string) string {

	cookie, err := ctx.r.Cookie(key)

	if err != nil {
		return cookie.Value
	}

	return ""
}

// Set persistent cookie
func (ctx *Context) SetPersistentCookie(key string, value string, duration time.Duration) {
	expiration := time.Now().Add(duration)
	cookie := http.Cookie{Name: key, Value: value, Expires: expiration}
	http.SetCookie(ctx.w, &cookie)
}

// Unset cookie
func (ctx *Context) DeleteCookie(key string) {
	ctx.AddResponseHeader("Set-Cookie", key+"=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
}

func (ctx *Context) GetUploadFile(inputName string) (string, io.ReadCloser, error) {
	ctx.r.ParseMultipartForm(MAX_MULTIPART_MEMORY)
	var file io.ReadCloser
	file, handler, err := ctx.r.FormFile(inputName)
	if err != nil {
		return "", nil, err
	}
	fileName := handler.Filename

	if file == nil {
		file, err = handler.Open()
		if err != nil {
			return "", nil, err
		}
	}

	return fileName, file, nil
}
