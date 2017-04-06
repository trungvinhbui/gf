package gf

import (
	"crypto/md5"
	"database/sql"
	"encoding/gob"
	"errors"
	"fmt"
	"github.com/goframework/gf/cfg"
	"github.com/goframework/gf/ext"
	"github.com/goframework/gf/securecookie"
	"github.com/goframework/gf/sessions"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

const MAX_MULTIPART_MEMORY = 1024 * 1024 * 5

var mGobRegisted = make(map[string]bool)

type Context struct {
	w               http.ResponseWriter
	r               *http.Request
	vars            map[string]interface{}
	isSelfResponse  bool
	httpResponeCode int

	Config         *cfg.Cfg
	RouteVars      map[string]ext.Var
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

	TemplateFunc map[string]interface{}
	DB           *sql.DB
}

func (ctx *Context) Cleanup() {
	if ctx != nil {
		if ctx.r != nil {
			if ctx.r.MultipartForm != nil {
				ctx.r.MultipartForm.RemoveAll()
			}
			if ctx.r.Body != nil {
				ctx.r.Body.Close()
			}
		}
		if ctx.DB != nil {
			ctx.DB.Close()
		}
	}
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
	ctx.Session.ID = securecookie.NewID()
	ctx.Session.IsNew = true
}

func (ctx *Context) SetSessionFlash(key string, value interface{}) {
	varType := reflect.TypeOf(value).String()
	if !mGobRegisted[varType] {
		if !mGobRegisted[varType] {
			gob.Register(value)
			mGobRegisted[varType] = true
		}
	}

	ctx.Session.AddFlash(value, key)
}

func (ctx *Context) GetSessionFlash(key string) interface{} {
	vars := ctx.Session.Flashes(key)
	if len(vars) > 0 {
		return vars[0]
	}
	return nil
}

func (ctx *Context) WriteHttpStatus(httpStatus int) {
	ctx.w.WriteHeader(httpStatus)
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

func (ctx *Context) GetUploadFile(inputName string) (*FormFile, error) {
	f := ctx.Form.File(inputName)

	if f == nil {
		return nil, http.ErrMissingFile
	}

	return f, nil
}

func (ctx *Context) ServeStaticFile(filePath string, isAttachment bool) {
	ctx.isSelfResponse = true
	if ext.FileExists(filePath) {
		fileName := filepath.Base(filePath)
		if isAttachment {
			ctx.w.Header().Add("Content-Disposition", "attachment; filename="+fileName)
		} else {
			ctx.w.Header().Add("Content-Disposition", "inline; filename="+fileName)
		}
		http.ServeFile(ctx.w, ctx.r, filePath)
	} else {
		ctx.w.WriteHeader(http.StatusNotFound)
		ctx.w.Write([]byte("404 - Not found"))
	}
}

type cacheObject struct {
	ExpiredAt time.Time
	Data      interface{}
}

func (ctx *Context) LoadCache(key string, object interface{}) error {
	cacheDir := ctx.Config.Str("Server.CacheStoreDir", "./cache")
	cacheDir, err := filepath.Abs(cacheDir)
	if err != nil {
		return err
	}

	path := filepath.Join(cacheDir, fmt.Sprintf("%x", md5.Sum([]byte(key))))
	pathExpireTime := path + "_expire_time"

	fileExpireTime, err := os.Open(pathExpireTime)
	if err != nil {
		return err
	}
	var extTimeUnix int64
	fmt.Fscan(fileExpireTime, &extTimeUnix)
	fileExpireTime.Close()

	extTime := time.Unix(extTimeUnix, 0)

	if extTime.Before(time.Now()) {
		os.Remove(pathExpireTime)
		os.Remove(path)

		return errors.New("Cache expired")
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := gob.NewDecoder(file)
	err = decoder.Decode(object)
	file.Close()

	//if err == nil {
	//	if cacheObj.ExpiredAt.Before(time.Now()) {
	//		object = nil
	//	}
	//}

	return err
}

func (ctx *Context) SaveCache(key string, object interface{}, secondTimeout int) error {
	cacheDir := ctx.Config.Str("Server.CacheStoreDir", DEFAULT_CACHE_STORE_DIR)
	cacheDir, err := filepath.Abs(cacheDir)
	if err != nil {
		return err
	}

	if !ext.FolderExists(cacheDir) {
		os.MkdirAll(cacheDir, os.ModePerm)
	}

	path := filepath.Join(cacheDir, fmt.Sprintf("%x", md5.Sum([]byte(key))))
	pathExpireTime := path + "_expire_time"

	file, err := os.Create(path)
	if err == nil {
		encoder := gob.NewEncoder(file)
		encoder.Encode(object)
	}
	file.Close()

	fileExpireTime, err := os.Create(pathExpireTime)
	if err == nil {
		fmt.Fprint(fileExpireTime, time.Now().Add(time.Duration(secondTimeout)*time.Second).Unix())
	}
	fileExpireTime.Close()

	return err
}

func (ctx *Context) GetRequestIP() string {
	ip, _, err := net.SplitHostPort(ctx.r.RemoteAddr)
	if err != nil {
		userIP := net.ParseIP(ip)
		if userIP != nil {
			ip = userIP.String()
		}
	}

	return ip
}

func (ctx *Context) GetRequestForwardedIP() string {

	ip := ctx.r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = ctx.r.Header.Get("x-forwarded-for")
	}
	if ip == "" {
		ip = ctx.r.Header.Get("X-FORWARDED-FOR")
	}

	return ip
}

func (ctx *Context) GetBrowserAgent() string {
	agent := ctx.r.Header.Get("User-Agent")
	if agent == "" {
		agent = ctx.r.Header.Get("user-agent")
	}
	if agent == "" {
		agent = ctx.r.Header.Get("USER-AGENT")
	}

	return agent
}
