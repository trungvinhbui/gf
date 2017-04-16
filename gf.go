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
	"github.com/goframework/gf/fsgzip"
	"github.com/goframework/gf/html/template"
	"github.com/goframework/gf/sessions"
	"github.com/tdewolff/minify"
	"github.com/tdewolff/minify/html"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"
)

const (
	CFG_KEY_SERVER_STATIC_DIR          = "Server.StaticDir"
	CFG_KEY_SERVER_STATIC_MAX_CACHE_FZ = "Server.StaticMaxCacheFileSize"
	CFG_KEY_SERVER_VIEW_DIR            = "Server.ViewDir"
	CFG_KEY_SERVER_STATIC_WEB_PATH     = "Server.StaticWebPath"
	CFG_KEY_SERVER_ADDR                = "Server.Addr"
	CFG_KEY_SERVER_READ_TIMEOUT        = "Server.ReadTimeout"
	CFG_KEY_SERVER_WRITE_TIMEOUT       = "Server.WriteTimeout"
	CFG_KEY_SERVER_MAX_HEADER_BYTES    = "Server.MaxHeaderBytes"
	CFG_KEY_SERVER_MAX_CONTENT_LENGTH  = "Server.MaxContentLength"
	CFG_KEY_COOKIE_SECRET              = "Server.CookieSecret"
	CFG_KEY_SESSION_STORE_DIR          = "Server.SessionStoreDir"
	CFG_KEY_CACHE_STORE_DIR            = "Server.CacheStoreDir"
	CFG_KEY_SERVER_ENABLE_HTTP         = "Server.EnableHttp"
	CFG_KEY_SERVER_ENABLE_HTTPS        = "Server.EnableHttps"
	CFG_KEY_SERVER_ADDR_HTTPS          = "Server.AddrHttps"
	CFG_KEY_SERVER_CERT_FILE           = "Server.CertFile"
	CFG_KEY_SERVER_KEY_FILE            = "Server.KeyFile"
	CFG_KEY_SERVER_ENABLE_GZIP         = "Server.EnableGzip"
	CFG_KEY_SERVER_ENABLE_MINIFY       = "Server.EnableMinify"
	CFG_KEY_SERVER_FORCE_HTTPS         = "Server.ForceHttps"
	CFG_KEY_SERVER_ENABLE_CSRF_PROTECT = "Server.EnableCsrfProtect"
	CFG_KEY_SERVER_IP_REQUEST_LIMIT    = "Server.IPRequestLimit" //Limit request per IP per second (except static file requests), over limit will be reject with "429 Too Many Requests"
	CFG_KEY_DATABASE_DRIVER            = "Database.Driver"
	CFG_KEY_DATABASE_HOST              = "Database.Host"
	CFG_KEY_DATABASE_PORT              = "Database.Port"
	CFG_KEY_DATABASE_SERVER            = "Database.Server"
	CFG_KEY_DATABASE_USER              = "Database.User"
	CFG_KEY_DATABASE_PWD               = "Database.Pwd"
	CFG_KEY_DATABASE_SCHEMA            = "Database.DatabaseName"
)

const (
	DEFAULT_HTTP_PORT                  = ":80"
	DEFAULT_HTTPS_PORT                 = ":443"
	DEFAULT_SERVER_CONFIG_FILE         = "./server.cfg"
	DEFAULT_SERVER_STATIC_DIR          = "./static"
	DEFAULT_SERVER_STATIC_MAX_CACHE_FZ = 512 * 1024 //512KB
	DEFAULT_SERVER_STATIC_WEB_PATH     = "/static"
	DEFAULT_SERVER_VIEW_DIR            = "./view"
	DEFAULT_SERVER_ADDR                = ":8026"
	DEFAULT_SERVER_ADDR_HTTPS          = ":44326"
	DEFAULT_SERVER_CERT_FILE           = "./cert.pem"
	DEFAULT_SERVER_KEY_FILE            = "./key.pem"
	DEFAULT_SERVER_READ_TIMEOUT        = 120              //120s
	DEFAULT_SERVER_WRITE_TIMEOUT       = 120              //120s
	DEFAULT_SERVER_MAX_HEADER_BYTES    = 16 * 1024        //16KB
	DEFAULT_SERVER_MAX_CONTENT_LENGTH  = 10 * 1024 * 1024 //10MB
	DEFAULT_SERVER_ENABLE_GZIP         = true
	DEFAULT_SERVER_ENABLE_MINIFY       = false
	DEFAULT_SERVER_FORCE_HTTPS         = false
	DEFAULT_SERVER_ENABLE_CSRF_PROTECT = true
	DEFAULT_SERVER_IP_REQUEST_LIMIT    = 100 //100 request per second per IP
	DEFAULT_COOKIE_SECRET              = "COOKIE_SECRET"
	DEFAULT_SESSION_STORE_DIR          = "./session_store"
	DEFAULT_CACHE_STORE_DIR            = "./cache_store"
	DEFAULT_SERVER_ENABLE_HTTP         = true
	DEFAULT_SERVER_ENABLE_HTTPS        = false
	DEFAULT_SERVER_ENABLE_HTTP2        = true
)

const (
	SERVER_SESSION_ID         = "session_id"
	SERVER_SESSION_MAX_LENGTH = 128 * 1024 //128KB
	SERVER_SESSION_KEEP_DAY   = 7          // 1 week

	METHOD_GET  = "GET"
	METHOD_POST = "POST"

	_IS_CSRF_PROTECTED = "_IS_CSRF_PROTECTED"
)

var _GZIP_ENABLE_EXT = map[string]bool{
	".css":  true,
	".htm":  true,
	".html": true,
	".js":   true,
	".json": true,
	".svg":  true,
	".txt":  true,
	".xml":  true,
}

var mStaticDir string
var mViewDir string
var mStaticWebPath string
var mSessionStoreDir string
var mCacheStoreDir string
var mEnableGzip = true
var mEnableMinify = false
var mForceHttps = false
var mMaxContentLength int64

var mServerHttpAddr string
var mServerHttpsAddr string

var mCfg cfg.Cfg = cfg.Cfg{}

type patternFunc struct {
	Pattern    string
	Methods    []string
	HandleFunc func(*Context)
}

var mListFilter []patternFunc
var mRootRouter rootRouter = rootRouter{}
var mHandle404 func(http.ResponseWriter, *http.Request)
var mView404 string
var mDBFactory *db.SqlDBFactory
var mCsrfProtection *csrf.CsrfProtection

var mSessionStore *sessions.FilesystemStore
var mHtmlMinifier *minify.M

// Start web server
func Run() {
	var err error

	mCfg.Load(DEFAULT_SERVER_CONFIG_FILE)

	cfStaticDir := mCfg.Str(CFG_KEY_SERVER_STATIC_DIR, DEFAULT_SERVER_STATIC_DIR)
	cfViewDir := mCfg.Str(CFG_KEY_SERVER_VIEW_DIR, DEFAULT_SERVER_VIEW_DIR)

	cfAddr := mCfg.Str(CFG_KEY_SERVER_ADDR, DEFAULT_SERVER_ADDR)
	cfReadTimeout := mCfg.Int(CFG_KEY_SERVER_READ_TIMEOUT, DEFAULT_SERVER_READ_TIMEOUT)
	cfWriteTimeout := mCfg.Int(CFG_KEY_SERVER_WRITE_TIMEOUT, DEFAULT_SERVER_WRITE_TIMEOUT)
	cfMaxHeaderBytes := mCfg.Int(CFG_KEY_SERVER_MAX_HEADER_BYTES, DEFAULT_SERVER_MAX_HEADER_BYTES)
	mMaxContentLength = mCfg.Int64(CFG_KEY_SERVER_MAX_CONTENT_LENGTH, DEFAULT_SERVER_MAX_CONTENT_LENGTH)
	mIPRequestLimit = mCfg.Int(CFG_KEY_SERVER_IP_REQUEST_LIMIT, DEFAULT_SERVER_IP_REQUEST_LIMIT)
	mFileCacheMaxSize = mCfg.Int64(CFG_KEY_SERVER_STATIC_MAX_CACHE_FZ, DEFAULT_SERVER_STATIC_MAX_CACHE_FZ)
	cfCookieSecret := mCfg.Str(CFG_KEY_COOKIE_SECRET, DEFAULT_COOKIE_SECRET)
	cfSessionStoreDir := mCfg.Str(CFG_KEY_SESSION_STORE_DIR, DEFAULT_SESSION_STORE_DIR)
	cfCacheStoreDir := mCfg.Str(CFG_KEY_CACHE_STORE_DIR, DEFAULT_CACHE_STORE_DIR)
	cfEnableHttp := mCfg.Bool(CFG_KEY_SERVER_ENABLE_HTTP, DEFAULT_SERVER_ENABLE_HTTP)
	cfEnableHttps := mCfg.Bool(CFG_KEY_SERVER_ENABLE_HTTPS, DEFAULT_SERVER_ENABLE_HTTPS)
	cfAddrHttps := mCfg.Str(CFG_KEY_SERVER_ADDR_HTTPS, DEFAULT_SERVER_ADDR_HTTPS)
	cfCertFile := mCfg.Str(CFG_KEY_SERVER_CERT_FILE, DEFAULT_SERVER_CERT_FILE)
	cfKeyFile := mCfg.Str(CFG_KEY_SERVER_KEY_FILE, DEFAULT_SERVER_KEY_FILE)

	mServerHttpAddr = cfAddr
	mServerHttpsAddr = cfAddrHttps

	mEnableMinify = mCfg.Bool(CFG_KEY_SERVER_ENABLE_MINIFY, DEFAULT_SERVER_ENABLE_MINIFY)
	mEnableGzip = mCfg.Bool(CFG_KEY_SERVER_ENABLE_GZIP, DEFAULT_SERVER_ENABLE_GZIP)
	mForceHttps = mCfg.Bool(CFG_KEY_SERVER_FORCE_HTTPS, DEFAULT_SERVER_FORCE_HTTPS)
	cfEnableCsrfProtect := mCfg.Bool(CFG_KEY_SERVER_ENABLE_CSRF_PROTECT, DEFAULT_SERVER_ENABLE_CSRF_PROTECT)

	cfDatabaseDriver := mCfg.Str(CFG_KEY_DATABASE_DRIVER, "")
	cfDatabaseHost := mCfg.Str(CFG_KEY_DATABASE_HOST, "")
	cfDatabasePort := mCfg.Int(CFG_KEY_DATABASE_PORT, 0)
	cfDatabaseServer := mCfg.Str(CFG_KEY_DATABASE_SERVER, "")

	cfDatabaseUser := mCfg.Str(CFG_KEY_DATABASE_USER, "")
	cfDatabasePwd := mCfg.Str(CFG_KEY_DATABASE_PWD, "")
	cfDatabaseName := mCfg.Str(CFG_KEY_DATABASE_SCHEMA, "")

	mStaticWebPath = mCfg.Str(CFG_KEY_SERVER_STATIC_WEB_PATH, DEFAULT_SERVER_STATIC_WEB_PATH)
	if !strings.HasPrefix(mStaticWebPath, "/") {
		mStaticWebPath = "/" + mStaticWebPath
	}
	if !strings.HasSuffix(mStaticWebPath, "/") {
		mStaticWebPath = mStaticWebPath + "/"
	}

	if mEnableMinify {
		mHtmlMinifier = minify.New()
		mHtmlMinifier.AddFunc("html", html.Minify)
	}

	if cfDatabaseServer == "" {
		cfDatabaseServer = fmt.Sprintf("%s:%d", cfDatabaseHost, cfDatabasePort)
	}

	mDBFactory = &db.SqlDBFactory{
		Driver:   cfDatabaseDriver,
		Server:   cfDatabaseServer,
		User:     cfDatabaseUser,
		Pwd:      cfDatabasePwd,
		Database: cfDatabaseName,
	}

	if !cfEnableHttp && !cfEnableHttps {
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

	if cfEnableCsrfProtect {
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

	if cfEnableHttp {
		go func() {
			log.Println("Http server start at " + cfAddr)
			err := serverHttp.ListenAndServe()
			errChanHttp <- err
			log.Println("Http server stopted")
		}()
	}

	if cfEnableHttps {
		go func() {
			log.Println("Https server start at " + cfAddrHttps)

			serverHttps.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}

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

/*Filter add a filter to request handler,
- pattern used wildcard matching with ? and *
- all request methods (GET/POST/PUT/HEAD/...) will be applied
*/
func Filter(pattern string, f func(*Context)) {
	mListFilter = append(mListFilter, patternFunc{
		Pattern:    pattern,
		HandleFunc: f,
	})
}

func HandleGetPost(pattern string, f func(*Context)) {
	var err error
	err = mRootRouter.Add(METHOD_GET, pattern, f)
	if err != nil {
		log.Println(err)
	}
	err = mRootRouter.Add(METHOD_POST, pattern, f)
	if err != nil {
		log.Println(err)
	}
}

func HandleGet(pattern string, f func(*Context)) {
	err := mRootRouter.Add(METHOD_GET, pattern, f)
	if err != nil {
		log.Println(err)
	}
}

func HandlePost(pattern string, f func(*Context)) {
	err := mRootRouter.Add(METHOD_POST, pattern, f)
	if err != nil {
		log.Println(err)
	}
}

func HandleMethod(pattern string, f func(*Context), method string) {
	err := mRootRouter.Add(method, pattern, f)
	if err != nil {
		log.Println(err)
	}
}

func Handle404(f func(http.ResponseWriter, *http.Request)) {
	mHandle404 = f
}

func Set404View(viewPath string) {
	mView404 = viewPath
}

type gfHandler struct{}

func (*gfHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[RECOVER]: %v\r\n\t%s\r\n", rec, debug.Stack())
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
		}
	}()

	if r.ContentLength > mMaxContentLength {
		http.Error(w, "413 - Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, mMaxContentLength)

	urlPath := r.URL.EscapedPath()

	if mForceHttps {
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
	if strings.LastIndex(urlPath, "/") == 0 &&
		strings.LastIndex(urlPath, "\\") < 0 &&
		strings.LastIndex(urlPath, ".") > 0 &&
		ext.FileExists(mStaticDir+urlPath) {
		urlPath = mStaticWebPath + urlPath[1:]
	}

	if strings.HasPrefix(urlPath, mStaticWebPath) {
		if r.Method == METHOD_GET {
			urlPath = urlPath[len(mStaticWebPath):]
			staticFile, err := filepath.Abs(mStaticDir + urlPath)
			if err == nil && strings.HasPrefix(staticFile, mStaticDir) && ext.FileExists(staticFile) {
				w.Header().Add("Cache-Control", "max-age=0, must-revalidate")

				fc, err := getFileCache(staticFile)

				if err != nil {
					log.Printf("Static cache error: %v", err)
					http.Error(w, "422 - Unprocessable Entity", http.StatusUnprocessableEntity)
					return
				}

				if fc != nil {
					serveCacheFile(w, r, fc)
					return
				}

				if mEnableGzip && isGzipEnable(staticFile) {
					fsgzip.ServeFile(w, r, staticFile)
				} else {
					http.ServeFile(w, r, staticFile)
				}
				return
			}
		}

		//Not GET method or file not exist
		http.Error(w, "404 - Not found", http.StatusNotFound)
		return
	}

	if overIPLimit(w, r) {
		http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
		return
	}

	var context *Context = nil
	defer func() {
		if context != nil {
			context.Cleanup()
		}
	}()

	handler, vars := mRootRouter.Route(r.Method, urlPath)

	//Only do filter when exists handler
	if handler != nil {
		context = createContext(w, r)
		if !csrfProtectHTTP(context) {
			return
		}
		context.RouteVars = vars

		for _, pf := range mListFilter {
			if ext.WildMatch(pf.Pattern, urlPath) {
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

		handler(context)
		context.Session.Save(r, w)
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

	if mHandle404 != nil {
		mHandle404(w, r)
		return
	}
	if len(mView404) > 0 {
		view404File := filepath.Join(mViewDir, mView404)
		fc, _ := getFileCache(view404File)
		if fc != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			w.Write(fc.Data)
			return
		}
	}
	http.Error(w, "404 - Not found", http.StatusNotFound)
}

func isGzipEnable(file string) bool {
	return _GZIP_ENABLE_EXT[strings.ToLower(filepath.Ext(file))]
}

type NullCloseWriter struct {
	w io.Writer
}

func (ncw *NullCloseWriter) Write(p []byte) (n int, err error) {
	return ncw.w.Write(p)
}

func (w *NullCloseWriter) Close() error {
	return nil
}

func renderView(context *Context) {
	if context.JsonResponse != nil {
		var wc io.WriteCloser
		wc = &NullCloseWriter{context.w}
		if mEnableGzip {
			context.w.Header().Set("Content-Encoding", "gzip")
			wc = gzip.NewWriter(context.w)
		}

		context.w.Header().Add("Content-Type", "application/json; charset=utf-8")
		context.w.WriteHeader(context.httpResponeCode)

		jsonEncoder := json.NewEncoder(wc)
		err := jsonEncoder.Encode(context.JsonResponse)
		if err != nil {
			log.Println("Error while encoding JSON:\n" + err.Error())
		}

		wc.Close()
		return
	}

	var viewFiles []string
	if context.ViewBases != nil {
		viewFiles = make([]string, len(context.ViewBases))
		for i, tmpl := range context.ViewBases {
			viewFiles[i] = tmpl
		}
	}
	if context.View != "" {
		viewFiles = append(viewFiles, context.View)
	}
	if len(viewFiles) > 0 {
		tem, err := ParseTemplateFiles(context.TemplateFunc, viewFiles...)
		if err != nil {
			log.Println("Error while parsing template:\n" + err.Error())
			http.Error(context.w, "ParseFiles: "+err.Error(), http.StatusInternalServerError)
			return
		}
		var wc io.WriteCloser
		wc = &NullCloseWriter{context.w}

		if mEnableGzip {
			context.w.Header().Set("Content-Encoding", "gzip")
			wc = gzip.NewWriter(context.w)
		}
		contentType := context.w.Header().Get("Content-Type")
		if contentType == "" {
			contentType = "text/html; charset=utf-8"
			context.w.Header().Set("Content-Type", contentType)
		}

		var wc2 io.WriteCloser
		wc2 = wc
		if mEnableMinify && strings.Contains(contentType, "text/html") {
			wc2 = mHtmlMinifier.Writer("html", wc)
		}

		context.w.WriteHeader(context.httpResponeCode)
		err = tem.Execute(wc2, context.ViewData)

		if err != nil {
			log.Println("Error while executing template:\n" + err.Error())
		}

		wc2.Close()
		if wc != wc2 {
			wc.Close()
		}
	}
}

func startDeleteSessionStoreJob() {
	go func() {
		for true {
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

			time.Sleep(24 * time.Hour)
		}
	}()
}

func cleanUpCacheDir(dir string) (countFile int, empty bool) {
	files, err := ioutil.ReadDir(dir)
	now := time.Now()
	countFile = 0
	if err == nil {
		for _, f := range files {
			subPath := filepath.Join(dir, f.Name())
			if f.IsDir() {
				countSubFiles, empty := cleanUpCacheDir(subPath)
				countFile += countSubFiles
				if empty && f.ModTime().Before(time.Now().AddDate(0, 0, -1)) {
					os.Remove(subPath)
				}
			} else if strings.HasSuffix(subPath, "_expire_time") {
				file, err := os.Open(subPath)
				if err == nil {
					var expTimeUnix int64
					fmt.Fscan(file, &expTimeUnix)
					file.Close()
					timeExp := time.Unix(expTimeUnix, 0)
					if timeExp.Before(now) {
						if os.Remove(subPath) == nil {
							countFile++
						}
						if os.Remove(strings.Replace(subPath, "_expire_time", "", 1)) == nil {
							countFile++
						}
					}
				}
			} else if f.ModTime().Before(time.Now().AddDate(0, 0, -1)) {
				if os.Remove(subPath) == nil {
					countFile++
				}
			}
		}
	}

	remainFiles, _ := ioutil.ReadDir(dir)
	empty = (len(remainFiles) == 0)

	return countFile, empty
}

func startDeleteCacheStoreJob() {

	go func() {
		for true {
			count, _ := cleanUpCacheDir(mCacheStoreDir)

			if count > 0 {
				log.Printf("Deleted %v cache files\r\n", count)
			}

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
		w:               w,
		r:               r,
		vars:            map[string]interface{}{},
		isSelfResponse:  false,
		httpResponeCode: http.StatusOK,
		Config:          &mCfg,
		Session:         session,
		UrlPath:         r.URL.Path,
		ViewData:        map[string]interface{}{},
		Method:          r.Method,
		IsGetMethod:     r.Method == METHOD_GET,
		IsPostMethod:    r.Method == METHOD_POST,
		IsUsingTSL:      r.TLS != nil,
		Host:            host,
		Form:            Form{r.Form, r},
		TemplateFunc:    map[string]interface{}{},
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

// Protect http request, return true if no problem happened

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
