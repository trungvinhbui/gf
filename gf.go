package gf

import (
	"github.com/goframework/gf/cfg"
	"github.com/goframework/gf/ext"
	"github.com/goframework/gf/html/template"
	"github.com/goframework/gf/sessions"
	"github.com/goframework/gf/fsgzip"
	"golang.org/x/net/http2"
	"log"
	"net/http"
	"path/filepath"
	"time"
	"os"
	"compress/gzip"
)

const DEFAULT_SERVER_CONFIG_FILE string = "./server.cfg"
const DEFAULT_SERVER_STATIC_DIR string = "./static"
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

const DEFAULT_SERVER_ENABLE_GZIP = 1

const DEFAULT_SERVER_ENABLE_HTTP = 1
const DEFAULT_SERVER_ENABLE_HTTPS = 0
const DEFAULT_SERVER_ENABLE_HTTP2 = 1

const SERVER_SESSION_ID string = "session_id"

const METHOD_GET string = "GET"
const METHOD_POST string = "POST"

var mStaticDir string
var mViewDir string
var mSessionStoreDir string
var mEnableGzip = 1

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

	mEnableGzip = mCfg.Int("Server.EnableGzip", DEFAULT_SERVER_ENABLE_GZIP)

	cfDatabaseDriver := mCfg.Str("Database.Driver", "")
	cfDatabaseHost := mCfg.Str("Database.Host", "")
	cfDatabasePort := mCfg.Int("Database.Port", 0)
	cfDatabaseUser := mCfg.Str("Database.User", "")
	cfDatabasePwd := mCfg.Str("Database.Pwd", "")
	cfDatabaseName := mCfg.Str("Database.DatabaseName", "")

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
				http2.ConfigureServer(serverHttps, nil)
			}

			err := serverHttps.ListenAndServeTLS(cfCertFile, cfKeyFile)
			errChanHttps <- err
			log.Println("Https server stopted")
		}()
	}

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
	staticFile := mStaticDir + path
	if ext.FileExists(staticFile) && r.Method == METHOD_GET {
		if mEnableGzip == 1 {
			fsgzip.ServeFile(w, r, staticFile)
		} else {
			http.ServeFile(w, r, staticFile)
		}
	} else {

		session, err := mSessionStore.Get(r, SERVER_SESSION_ID)
		if err != nil {
			session, err = mSessionStore.New(r, SERVER_SESSION_ID)
		}

		r.ParseForm()
		context := Context{
			w:              w,
			r:              r,
			isSelfResponse: false,
			Config:         &mCfg,
			Session:        session,
			UrlPath:        r.URL.Path,
			ViewData:       make(map[string]interface{}),
			Method:         r.Method,
			IsGetMethod:    r.Method == METHOD_GET,
			IsPostMethod:   r.Method == METHOD_POST,
			Form:           r.Form,
		}

		if mDBGen.IsEnable {
			context.DB = mDBGen.NewConnect()
			if context.DB != nil {
				defer context.DB.Close()
			}
		}

		for _, pf := range mListFilter {
			if ext.WildMatch(pf.Pattern, path) {
				pf.HandleFunc(&context)

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
				pf.HandleFunc(&context)
				context.Session.Save(r, w)
				/*-----------------------------*/

				if context.RedirectStatus != 0 {
					http.Redirect(w, r, context.RedirectPath, context.RedirectStatus)
					return
				}

				if context.isSelfResponse {
					return
				}

				renderView(&context)

				return
			}
		}

		context.w.WriteHeader(http.StatusNotFound)
		if mHandle404 != nil {
			mHandle404(&context)
			renderView(&context)
		} else {
			context.WriteS("404 - Not found")
		}
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
			http.Error(context.w, "ParseFiles: " + err.Error(), http.StatusInternalServerError)
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
