package gf

import (
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/goframework/gf/cfg"
	"github.com/goframework/gf/csrf"
	"github.com/goframework/gf/db"
	"github.com/goframework/gf/ext"
	"github.com/goframework/gf/exterror"
	"github.com/goframework/gf/fsgzip"
	"github.com/goframework/gf/html/template"
	"github.com/goframework/gf/sessions"
	"golang.org/x/net/http2"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DEFAULT_HTTP_PORT  = ":80"
const DEFAULT_HTTPS_PORT = ":443"

const DEFAULT_SERVER_CONFIG_FILE string = "./server.cfg"
const DEFAULT_SERVER_STATIC_DIR string = "./static"
const DEFAULT_SERVER_STATIC_WEB_PATH string = "/static"
const DEFAULT_SERVER_VIEW_DIR string = "./view"
const DEFAULT_SERVER_ADDR string = ":8026"
const DEFAULT_SERVER_ADDR_HTTPS string = ":44326"
const DEFAULT_SERVER_CERT_FILE string = "./cert.pem"
const DEFAULT_SERVER_KEY_FILE string = "./key.pem"
const DEFAULT_SERVER_READ_TIMEOUT = 120
const DEFAULT_SERVER_WRITE_TIMEOUT = 120
const DEFAULT_SERVER_MAX_HEADER_BYTES = 65536
const DEFAULT_COOKIE_SECRET string = "COOKIE_SECRET"
const DEFAULT_SESSION_STORE_DIR = "./session_store"
const DEFAULT_CACHE_STORE_DIR = "./cache_store"

const DEFAULT_SERVER_ENABLE_GZIP = 1
const DEFAULT_SERVER_FORCE_HTTPS = 0
const DEFAULT_SERVER_ENABLE_CSRF_PROTECT = 1

const DEFAULT_SERVER_ENABLE_HTTP = 1
const DEFAULT_SERVER_ENABLE_HTTPS = 0
const DEFAULT_SERVER_ENABLE_HTTP2 = 1

const SERVER_SESSION_ID string = "session_id"
const SERVER_SESSION_MAX_LENGTH = 131072 //128KB
const SERVER_SESSION_KEEP_DAY = 7 // 1 week

const METHOD_GET string = "GET"
const METHOD_POST string = "POST"

const _IS_CSRF_PROTECTED string = "_IS_CSRF_PROTECTED"

var mStaticDir string
var mViewDir string
var mStaticWebPath string
var mSessionStoreDir string
var mCacheStoreDir string
var mEnableGzip = 1
var mForceHttps = 0

var mServerHttpAddr string
var mServerHttpsAddr string

var mCfg cfg.Cfg = cfg.Cfg{}

type patternFunc struct {
	Pattern    string
	Methods    []string
	HandleFunc func(*Context)
}

var mListFilter []patternFunc
var mListHandle []patternFunc
var mHandle404 func(*Context)
var mDBFactory *db.SqlDBFactory
var mCsrfProtection *csrf.CsrfProtection

var mSessionStore *sessions.FilesystemStore

// Start web server
func Run() {
	var err error

	mCfg.Load(DEFAULT_SERVER_CONFIG_FILE)

	cfStaticDir := mCfg.Str("Server.StaticDir", DEFAULT_SERVER_STATIC_DIR)
	cfViewDir := mCfg.Str("Server.ViewDir", DEFAULT_SERVER_VIEW_DIR)

	cfAddr := mCfg.Str("Server.Addr", DEFAULT_SERVER_ADDR)
	cfReadTimeout := mCfg.Int("Server.ReadTimeout", DEFAULT_SERVER_READ_TIMEOUT)
	cfWriteTimeout := mCfg.Int("Server.WriteTimeout", DEFAULT_SERVER_WRITE_TIMEOUT)
	cfMaxHeaderBytes := mCfg.Int("Server.MaxHeaderBytes", DEFAULT_SERVER_MAX_HEADER_BYTES)
	cfCookieSecret := mCfg.Str("Server.CookieSecret", DEFAULT_COOKIE_SECRET)
	cfSessionStoreDir := mCfg.Str("Server.SessionStoreDir", DEFAULT_SESSION_STORE_DIR)
	cfCacheStoreDir := mCfg.Str("Server.CacheStoreDir", DEFAULT_CACHE_STORE_DIR)
	cfEnableHttp := mCfg.Int("Server.EnableHttp", DEFAULT_SERVER_ENABLE_HTTP)
	cfEnableHttps := mCfg.Int("Server.EnableHttps", DEFAULT_SERVER_ENABLE_HTTPS)
	cfEnableHttp2 := mCfg.Int("Server.EnableHttp2", DEFAULT_SERVER_ENABLE_HTTP2)
	cfAddrHttps := mCfg.Str("Server.AddrHttps", DEFAULT_SERVER_ADDR_HTTPS)
	cfCertFile := mCfg.Str("Server.CertFile", DEFAULT_SERVER_CERT_FILE)
	cfKeyFile := mCfg.Str("Server.KeyFile", DEFAULT_SERVER_KEY_FILE)

	mServerHttpAddr = cfAddr
	mServerHttpsAddr = cfAddrHttps

	mEnableGzip = mCfg.Int("Server.EnableGzip", DEFAULT_SERVER_ENABLE_GZIP)
	mForceHttps = mCfg.Int("Server.ForceHttps", DEFAULT_SERVER_FORCE_HTTPS)
	cfEnableCsrfProtect := mCfg.Int("Server.EnableCsrfProtect", DEFAULT_SERVER_ENABLE_CSRF_PROTECT)

	cfDatabaseDriver := mCfg.Str("Database.Driver", "")
	cfDatabaseHost := mCfg.Str("Database.Host", "")
	cfDatabasePort := mCfg.Int("Database.Port", 0)
	cfDatabaseServer := mCfg.Str("Database.Server", "")

	cfDatabaseUser := mCfg.Str("Database.User", "")
	cfDatabasePwd := mCfg.Str("Database.Pwd", "")
	cfDatabaseName := mCfg.Str("Database.DatabaseName", "")

	mStaticWebPath = mCfg.Str("Server.StaticWebPath", DEFAULT_SERVER_STATIC_WEB_PATH)
	if !strings.HasPrefix(mStaticWebPath, "/") {
		mStaticWebPath = "/" + mStaticWebPath
	}
	if !strings.HasSuffix(mStaticWebPath, "/") {
		mStaticWebPath = mStaticWebPath + "/"
	}

	if cfDatabaseServer == "" {
		cfDatabaseServer = fmt.Sprintf("%s:%d",cfDatabaseHost, cfDatabasePort)
	}

	mDBFactory = &db.SqlDBFactory{
		Driver:   cfDatabaseDriver,
		Server:   cfDatabaseServer,
		User:     cfDatabaseUser,
		Pwd:      cfDatabasePwd,
		Database: cfDatabaseName,
	}

	if cfEnableHttp == 0 && cfEnableHttps == 0 {
		log.Fatal("No server enabled. At least Server.EnableHttp or Server.EnableHttps have to not zero.")
	}

	mStaticDir, err = filepath.Abs(cfStaticDir)
	if err != nil {
		log.Fatal(err)
	}
	separator := fmt.Sprintf("%c", filepath.Separator)
	if !strings.HasSuffix(mStaticDir, separator) {
		mStaticDir = mStaticDir + separator
	}

	mViewDir, err = filepath.Abs(cfViewDir)
	if err != nil {
		log.Fatal(err)
	}

	mSessionStoreDir, err = filepath.Abs(cfSessionStoreDir)
	if err != nil {
		log.Fatal(err)
	}
	os.MkdirAll(mSessionStoreDir, os.ModePerm)

	mCacheStoreDir, err = filepath.Abs(cfCacheStoreDir)
	if err != nil {
		log.Fatal(err)
	}
	os.MkdirAll(mCacheStoreDir, os.ModePerm)

	if err = mDBFactory.Check(); err != nil {
		log.Fatal(err)
	}

	mSessionStore = sessions.NewFilesystemStore(mSessionStoreDir, []byte(cfCookieSecret))
	mSessionStore.MaxLength(SERVER_SESSION_MAX_LENGTH)
	mSessionStore.MaxAge(0) // session only

	if cfEnableCsrfProtect != 0 {
		mCsrfProtection = csrf.InitCsrf([]byte(cfCookieSecret), csrf.Secure(false))
	}

	serverHttp := &http.Server{
		Addr:           cfAddr,
		ReadTimeout:    time.Duration(cfReadTimeout) * time.Second,
		WriteTimeout:   time.Duration(cfWriteTimeout) * time.Second,
		MaxHeaderBytes: cfMaxHeaderBytes,
		Handler:        &gfHandler{},
	}

	serverHttps := &http.Server{
		Addr:           cfAddrHttps,
		ReadTimeout:    time.Duration(cfReadTimeout) * time.Second,
		WriteTimeout:   time.Duration(cfWriteTimeout) * time.Second,
		MaxHeaderBytes: cfMaxHeaderBytes,
		Handler:        &gfHandler{},
	}

	errChanHttp := make(chan error)
	errChanHttps := make(chan error)

	if cfEnableHttp != 0 {
		go func() {
			log.Println("Http server start at " + cfAddr)
			err := serverHttp.ListenAndServe()
			errChanHttp <- err
			log.Println("Http server stopted")
		}()
	}

	if cfEnableHttps != 0 {
		go func() {
			log.Println("Https server start at " + cfAddrHttps)

			if cfEnableHttp2 != 0 {
				http2.VerboseLogs = false
				http2.ConfigureServer(serverHttps, nil)
			} else {
				serverHttps.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
			}

			err := serverHttps.ListenAndServeTLS(cfCertFile, cfKeyFile)
			errChanHttps <- err
			log.Println("Https server stopted")
		}()
	}

	startDeleteSessionStoreJob()
	startDeleteCacheStoreJob()

	select {
	case err := <-errChanHttp:
		log.Printf("ListenAndServe error: %s", err)
	case err := <-errChanHttps:
		log.Printf("ListenAndServeTLS error: %s", err)
	}
}

func Filter(pattern string, f func(*Context)) {
	mListFilter = append(mListFilter, patternFunc{
		Pattern:    pattern,
		HandleFunc: f,
	})
}

func HandleGetPost(pattern string, f func(*Context)) {
	mListHandle = append(mListHandle, patternFunc{
		Pattern:    pattern,
		HandleFunc: f,
		Methods:    []string{METHOD_GET, METHOD_POST},
	})
}

func HandleGet(pattern string, f func(*Context)) {
	mListHandle = append(mListHandle, patternFunc{
		Pattern:    pattern,
		HandleFunc: f,
		Methods:    []string{METHOD_GET},
	})
}

func HandlePost(pattern string, f func(*Context)) {
	mListHandle = append(mListHandle, patternFunc{
		Pattern:    pattern,
		HandleFunc: f,
		Methods:    []string{METHOD_POST},
	})
}

func HandleMethod(pattern string, f func(*Context), method string) {
	mListHandle = append(mListHandle, patternFunc{
		Pattern:    pattern,
		HandleFunc: f,
		Methods:    []string{method},
	})
}

func Handle404(f func(*Context)) {
	mHandle404 = f
}

type gfHandler struct{}

func (*gfHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[RECOVER]: %v\r\n", r)
		}
	}()

	r.Close = true
	
	path := r.URL.EscapedPath()

	if mForceHttps != 0 {
		if r.TLS == nil {
			host := getHost(r)
			httpsUrl := "https://" + host
			if mServerHttpsAddr != DEFAULT_HTTPS_PORT {
				httpsUrl = httpsUrl + mServerHttpsAddr
			}

			http.Redirect(w, r, httpsUrl, http.StatusFound)
			return
		}
	}

	//Root static files (robots.txt, favicon.icon, ...)
	if strings.LastIndex(path, "/") == 0 &&
		strings.LastIndex(path, "\\") < 0 &&
		strings.LastIndex(path, ".") > 0 &&
		ext.FileExists(mStaticDir + path) {
		path = mStaticWebPath + path[1:]
	}

	if strings.HasPrefix(path, mStaticWebPath) {
		if r.Method == METHOD_GET {
			path = path[len(mStaticWebPath):]
			staticFile, err := filepath.Abs(mStaticDir + path)
			if err == nil && strings.HasPrefix(staticFile, mStaticDir) && ext.FileExists(staticFile) {
				w.Header().Add("Cache-Control", "max-age=0, must-revalidate")
				if mEnableGzip == 1 {
					fsgzip.ServeFile(w, r, staticFile)
				} else {
					http.ServeFile(w, r, staticFile)
				}
				return
			}
		}

		//Not GET method or file not exist
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 - Not found"))
		return
	}

	var context *Context = nil
	defer func() {
		if context != nil {
			if context.DB != nil {
				context.DB.Close()
			}
		}
	}()

	for _, pf := range mListFilter {
		if ext.WildMatch(pf.Pattern, path) {
			if context == nil {
				context = createContext(w, r)
				if !csrfProtectHTTP(context) {
					return
				}
			}

			pf.HandleFunc(context)

			if context.RedirectStatus != 0 {
				context.Session.Save(r, w)
				http.Redirect(w, r, context.RedirectPath, context.RedirectStatus)
				return
			}

			if context.isSelfResponse {
				return
			}

			if context.FinishFilter {
				break
			}
		}
	}

	for _, pf := range mListHandle {
		methodMatched := ext.ArrayContains(pf.Methods, r.Method)
		if !methodMatched {
			continue
		}
		if vars, matched := ext.VarMatch(pf.Pattern, path); matched {
			/*-----------------------------*/
			if context == nil {
				context = createContext(w, r)
				if !csrfProtectHTTP(context) {
					return
				}
			}
			context.RouteVars = vars

			pf.HandleFunc(context)
			context.Session.Save(r, w)
			/*-----------------------------*/

			if context.RedirectStatus != 0 {
				http.Redirect(w, r, context.RedirectPath, context.RedirectStatus)
				return
			}

			if context.isSelfResponse {
				return
			}

			renderView(context)

			return
		}
	}

	w.WriteHeader(http.StatusNotFound)
	if mHandle404 != nil {
		if context == nil {
			context = createContext(w, r)
			if !csrfProtectHTTP(context) {
				return
			}
		}

		mHandle404(context)
		renderView(context)
	} else {
		w.Write([]byte("404 - Not found"))
	}
}

func renderView(context *Context) {

	if context.JsonResponse != nil {
		context.w.Header().Add("Content-Type", "application/json; charset=utf-8")
		jsonBytes, err := json.Marshal(context.JsonResponse)
		if err != nil {
			log.Println(exterror.WrapExtError(err))
			context.w.Write([]byte("{}"))
		}

		context.w.Write(jsonBytes)
		return
	}

	var viewFiles []string
	if context.ViewBases != nil {
		viewFiles = make([]string, len(context.ViewBases))
		for i, tmpl := range context.ViewBases {
			viewFiles[i] = mViewDir + "/" + tmpl
		}
	}
	if context.View != "" {
		viewFile := mViewDir + "/" + context.View
		viewFiles = append(viewFiles, viewFile)
	}
	if len(viewFiles) > 0 {
		tem, err := ParseTemplateFiles(context.TemplateFunc, viewFiles...)
		if err != nil {
			log.Println("Error while parsing template:\n" + err.Error())
			http.Error(context.w, "ParseFiles: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if mEnableGzip == 1 {
			context.w.Header().Set("Content-Encoding", "gzip")

			if context.w.Header().Get("Content-Type") == "" {
				context.w.Header().Set("Content-Type", "text/html; charset=utf-8")
			}

			gzWriter := gzip.NewWriter(context.w)
			err = tem.Execute(gzWriter, context.ViewData)
			gzWriter.Flush()

		} else {
			err = tem.Execute(context.w, context.ViewData)
		}

		if err != nil {
			log.Println("Error while executing template:\n" + err.Error())
		}
	}
}
func startDeleteSessionStoreJob() {
	go func() {
		for true {
			log.Println("Start delete session store !")

			files, err := ioutil.ReadDir(mSessionStoreDir)
			dayAgo := time.Now().AddDate(0, 0, -SERVER_SESSION_KEEP_DAY)
			count := 0
			if err == nil {
				for _, f := range files {
					if f.ModTime().Before(dayAgo) {
						if os.Remove(mSessionStoreDir+"/"+f.Name()) == nil {
							count++
						}
					}
				}
			}

			if count > 0 {
				log.Printf("Deleted %v session files\r\n", count)
			}

			log.Println("End delete session store !")
			time.Sleep(24 * time.Hour)
		}
	}()
}

func cleanUpCacheDir(dir string) (countFile int, empty bool) {
	files, err := ioutil.ReadDir(dir)
	now := time.Now()
	count := 0
	if err == nil {
		for _, f := range files {
			subPath := filepath.Join(dir, f.Name())
			if f.IsDir() {
				countSubFiles, empty := cleanUpCacheDir(subPath)
				count += countSubFiles
				if empty && f.ModTime().Before(time.Now().AddDate(0, 0, -1)) {
					os.Remove(subPath)
				}
			} else 	if strings.HasSuffix(subPath, "_expire_time") {
				file, err := os.Open(subPath)
				if err == nil {
					var expTimeUnix int64
					fmt.Fscan(file, &expTimeUnix)
					file.Close()
					timeExp := time.Unix(expTimeUnix, 0)
					if timeExp.Before(now) {
						if os.Remove(subPath) == nil {
							count++
						}
						if os.Remove(strings.Replace(subPath,"_expire_time","", 1)) == nil {
							count++
						}
					}
				}
			} else if f.ModTime().Before(time.Now().AddDate(0, 0, -1)) {
				if os.Remove(subPath) == nil {
					count++
				}
			}
		}
	}

	remainFiles, _ := ioutil.ReadDir(dir)
	empty = (len(remainFiles) == 0)

	return count, empty
}

func startDeleteCacheStoreJob() {

	go func() {
		for true {
			log.Println("Start delete cache store !")

			count, _ := cleanUpCacheDir(mCacheStoreDir)

			if count > 0 {
				log.Printf("Deleted %v cache files\r\n", count)
			}

			log.Println("End delete cache store !")
			time.Sleep(time.Hour)
		}
	}()
}

func createContext(w http.ResponseWriter, r *http.Request) *Context {
	host := getHost(r)

	session, err := mSessionStore.Get(r, SERVER_SESSION_ID)
	if err != nil {
		log.Println(err)
	}

	r.ParseMultipartForm(MAX_MULTIPART_MEMORY)

	context := Context{
		w:              w,
		r:              r,
		vars:           map[string]interface{}{},
		isSelfResponse: false,
		Config:         &mCfg,
		Session:        session,
		UrlPath:        r.URL.Path,
		ViewData:       map[string]interface{}{},
		Method:         r.Method,
		IsGetMethod:    r.Method == METHOD_GET,
		IsPostMethod:   r.Method == METHOD_POST,
		IsUsingTSL:     r.TLS != nil,
		Host:           host,
		Form:           Form{r.Form},
		TemplateFunc:   map[string]interface{}{},
	}

	if mDBFactory.IsEnable {
		context.DB = mDBFactory.NewConnect()
	}

	return &context
}

func getHost(r *http.Request) string {
	host := r.Host
	if r.TLS == nil {
		if strings.HasSuffix(r.Host, mServerHttpAddr) {
			host = host[:len(host)-len(mServerHttpAddr)]
		}
	} else {
		if strings.HasSuffix(r.Host, mServerHttpsAddr) {
			host = host[:len(host)-len(mServerHttpsAddr)]
		}
	}

	return host
}

// Protect http request, return true if no problem happend

// Protect is HTTP middleware that provides Cross-Site Request Forgery
// protection.
//
// It securely generates a masked (unique-per-request) token that
// can be embedded in the HTTP response (e.g. form field or HTTP header).
// The original (unmasked) token is stored in the session, which is inaccessible
// by an attacker (provided you are using HTTPS). Subsequent requests are
// expected to include this token, which is compared against the session token.
// Requests that do not provide a matching token are served with a HTTP 403
// 'Forbidden' error response.
func csrfProtectHTTP(ctx *Context) bool {
	// No CSRF protect
	if mCsrfProtection == nil {
		return true
	}

	if v, _ := ctx.GetBool(_IS_CSRF_PROTECTED); v {
		return true
	}

	// Retrieve the token from the session.
	// An error represents either a cookie that failed HMAC validation
	// or that doesn't exist.
	r := ctx.r
	w := ctx.w

	realToken, err := mCsrfProtection.St.Get(r)
	if err != nil || len(realToken) != csrf.TokenLength {
		// If there was an error retrieving the token, the token doesn't exist
		// yet, or it's the wrong length, generate a new token.
		// Note that the new token will (correctly) fail validation downstream
		// as it will no longer match the request token.
		realToken, err = csrf.GenerateRandomBytes(csrf.TokenLength)
		if err != nil {
			csrf.EnvError(r, err)
			mCsrfProtection.Opts.ErrorHandler.ServeHTTP(w, r)
			return false
		}

		// Save the new (real) token in the session store.
		err = mCsrfProtection.St.Save(realToken, w)
		if err != nil {
			csrf.EnvError(r, err)
			mCsrfProtection.Opts.ErrorHandler.ServeHTTP(w, r)
			return false
		}
	}

	csrfToken := csrf.Mask(realToken, r)

	ctx.ViewData["csrfKey"] = csrf.TokenKey
	ctx.ViewData["csrfToken"] = csrfToken
	ctx.ViewData[csrf.TemplateTag] = template.HTML(fmt.Sprintf(`<input type="hidden" name="%s" value="%s">`, csrf.TokenKey, csrfToken))

	// HTTP methods not defined as idempotent ("safe") under RFC7231 require
	// inspection.
	if !csrf.Contains(csrf.SafeMethods, r.Method) {
		// Enforce an origin check for HTTPS connections. As per the Django CSRF
		// implementation (https://goo.gl/vKA7GE) the Referer header is almost
		// always present for same-domain HTTP requests.
		if r.URL.Scheme == "https" {
			// Fetch the Referer value. Call the error handler if it's empty or
			// otherwise fails to parse.
			referer, err := url.Parse(r.Referer())
			if err != nil || referer.String() == "" {
				csrf.EnvError(r, csrf.ErrNoReferer)
				mCsrfProtection.Opts.ErrorHandler.ServeHTTP(w, r)
				return false
			}

			if csrf.SameOrigin(r.URL, referer) == false {
				csrf.EnvError(r, csrf.ErrBadReferer)
				mCsrfProtection.Opts.ErrorHandler.ServeHTTP(w, r)
				return false
			}
		}

		// If the token returned from the session store is nil for non-idempotent
		// ("unsafe") methods, call the error handler.
		if realToken == nil {
			csrf.EnvError(r, csrf.ErrNoToken)
			mCsrfProtection.Opts.ErrorHandler.ServeHTTP(w, r)
			return false
		}

		// Retrieve the combined token (pad + masked) token and unmask it.
		requestToken := csrf.Unmask(mCsrfProtection.RequestToken(r))

		// Compare the request token against the real token
		if !csrf.CompareTokens(requestToken, realToken) {
			csrf.EnvError(r, csrf.ErrBadToken)
			mCsrfProtection.Opts.ErrorHandler.ServeHTTP(w, r)
			return false
		}
	}

	// Set the Vary: Cookie header to protect clients from caching the response.
	w.Header().Add("Vary", "Cookie")
	ctx.Set(_IS_CSRF_PROTECTED, true)
	return true
}
