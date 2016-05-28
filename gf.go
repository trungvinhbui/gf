package gf

import (
	"compress/gzip"
	"fmt"
	"github.com/goframework/gf/cfg"
	"github.com/goframework/gf/csrf"
	"github.com/goframework/gf/ext"
	"github.com/goframework/gf/fsgzip"
	"github.com/goframework/gf/html/template"
	"github.com/goframework/gf/sessions"
	"golang.org/x/net/http2"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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
const DEFAULT_FAVICON_PATH = "/favicon.ico"

const DEFAULT_SERVER_ENABLE_GZIP = 1
const DEFAULT_SERVER_FORCE_HTTPS = 0

const DEFAULT_SERVER_ENABLE_HTTP = 1
const DEFAULT_SERVER_ENABLE_HTTPS = 0
const DEFAULT_SERVER_ENABLE_HTTP2 = 1

const SERVER_SESSION_ID string = "session_id"

const METHOD_GET string = "GET"
const METHOD_POST string = "POST"

var mStaticDir string
var mViewDir string
var mStaticWebPath string
var mSessionStoreDir string
var mEnableGzip = 1
var mForeHttps = 0

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
var mDBGen *sqlDBFactory

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
	cfEnableHttp := mCfg.Int("Server.EnableHttp", DEFAULT_SERVER_ENABLE_HTTP)
	cfEnableHttps := mCfg.Int("Server.EnableHttps", DEFAULT_SERVER_ENABLE_HTTPS)
	cfEnableHttp2 := mCfg.Int("Server.EnableHttp2", DEFAULT_SERVER_ENABLE_HTTP2)
	cfAddrHttps := mCfg.Str("Server.AddrHttps", DEFAULT_SERVER_ADDR_HTTPS)
	cfCertFile := mCfg.Str("Server.CertFile", DEFAULT_SERVER_CERT_FILE)
	cfKeyFile := mCfg.Str("Server.KeyFile", DEFAULT_SERVER_KEY_FILE)

	mServerHttpAddr = cfAddr
	mServerHttpsAddr = cfAddrHttps

	mEnableGzip = mCfg.Int("Server.EnableGzip", DEFAULT_SERVER_ENABLE_GZIP)
	mForeHttps = mCfg.Int("Server.ForceHttps", DEFAULT_SERVER_FORCE_HTTPS)

	cfDatabaseDriver := mCfg.Str("Database.Driver", "")
	cfDatabaseHost := mCfg.Str("Database.Host", "")
	cfDatabasePort := mCfg.Int("Database.Port", 0)
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

	mDBGen = &sqlDBFactory{
		cfDatabaseDriver,
		cfDatabaseHost,
		cfDatabasePort,
		cfDatabaseUser,
		cfDatabasePwd,
		cfDatabaseName,
		false,
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

	if err = mDBGen.Check(); err != nil {
		log.Fatal(err)
	}

	mSessionStore = sessions.NewFilesystemStore(mSessionStoreDir, []byte(cfCookieSecret))
	mSessionStore.MaxAge(0) // session only

	serverHttp := &http.Server{
		Addr:           cfAddr,
		ReadTimeout:    time.Duration(cfReadTimeout) * time.Second,
		WriteTimeout:   time.Duration(cfWriteTimeout) * time.Second,
		MaxHeaderBytes: cfMaxHeaderBytes,
		Handler:        csrf.Protect([]byte(cfCookieSecret), csrf.Secure(false))(&gfHandler{}),
	}

	serverHttps := &http.Server{
		Addr:           cfAddrHttps,
		ReadTimeout:    time.Duration(cfReadTimeout) * time.Second,
		WriteTimeout:   time.Duration(cfWriteTimeout) * time.Second,
		MaxHeaderBytes: cfMaxHeaderBytes,
		Handler:        csrf.Protect([]byte(cfCookieSecret), csrf.Secure(true))(&gfHandler{}),
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
				http2.ConfigureServer(serverHttps, nil)
			}

			err := serverHttps.ListenAndServeTLS(cfCertFile, cfKeyFile)
			errChanHttps <- err
			log.Println("Https server stopted")
		}()
	}

	startDeleteSessionStoreJob()

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
	path := r.URL.EscapedPath()

	if mForeHttps == 1 && r.TLS == nil {
		host := getHost(r)
		httpsUrl := "https://" + host
		if mServerHttpsAddr != DEFAULT_HTTPS_PORT {
			httpsUrl = httpsUrl + mServerHttpsAddr
		}

		http.Redirect(w, r, httpsUrl, http.StatusFound)
		return
	}

	if path == DEFAULT_FAVICON_PATH {
		path = mStaticWebPath + DEFAULT_FAVICON_PATH[1:]
	}
	if strings.HasPrefix(path, mStaticWebPath) {
		if r.Method == METHOD_GET {
			path = path[len(mStaticWebPath):]
			staticFile, err := filepath.Abs(mStaticDir + path)
			if err == nil && strings.HasPrefix(staticFile, mStaticDir) && ext.FileExists(staticFile) {
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

	for _, pf := range mListFilter {
		if ext.WildMatch(pf.Pattern, path) {
			if context == nil {
				context = createContext(w, r)
				if context.DB != nil {
					defer context.DB.Close()
				}
			}
			pf.HandleFunc(context)

			if context.RedirectStatus != 0 {
				http.Redirect(w, r, context.RedirectPath, context.RedirectStatus)
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
			context.RouteVars = vars
			/*-----------------------------*/
			if context == nil {
				context = createContext(w, r)
				if context.DB != nil {
					defer context.DB.Close()
				}
			}
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
			if context.DB != nil {
				defer context.DB.Close()
			}
		}
		mHandle404(context)
		renderView(context)
	} else {
		w.Write([]byte("404 - Not found"))
	}
}

func renderView(context *Context) {
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
		tem, err := template.ParseFiles(viewFiles...)
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
			monthAgo := time.Now().AddDate(0, -1, 0)
			count := 0
			if err == nil {
				for _, f := range files {
					if f.ModTime().Before(monthAgo) {
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

func createContext(w http.ResponseWriter, r *http.Request) *Context {
	host := getHost(r)

	session, err := mSessionStore.Get(r, SERVER_SESSION_ID)
	if err != nil {
		session, err = mSessionStore.New(r, SERVER_SESSION_ID)
	}

	r.ParseForm()
	csrfKey, csrfToken := csrf.TokenField(r)
	context := Context{
		w:              w,
		r:              r,
		isSelfResponse: false,
		Config:         &mCfg,
		Session:        session,
		UrlPath:        r.URL.Path,
		ViewData: map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"csrfKey":        csrfKey,
			"csrfToken":      csrfToken,
		},
		Method:       r.Method,
		IsGetMethod:  r.Method == METHOD_GET,
		IsPostMethod: r.Method == METHOD_POST,
		IsUsingTSL:   r.TLS != nil,
		Host:         host,
		Form:         Form{r.Form},
	}

	if mDBGen.IsEnable {
		context.DB = mDBGen.NewConnect()
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
