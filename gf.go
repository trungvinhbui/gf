package gf

import (
	"github.com/goframework/gf/cfg"
	"github.com/goframework/gf/ext"
	"github.com/goframework/gf/html/template"
	"github.com/goframework/gf/sessions"
	"log"
	"net/http"
	"path/filepath"
	"time"
)

const DEFAULT_SERVER_CONFIG_FILE string = "./server.cfg"
const DEFAULT_SERVER_STATIC_DIR string = "./static"
const DEFAULT_SERVER_VIEW_DIR string = "./view"
const DEFAULT_SERVER_ADDR string = ":8026"
const DEFAULT_SERVER_READ_TIMEOUT = 120
const DEFAULT_SERVER_WRITE_TIMEOUT = 120
const DEFAULT_SERVER_MAX_HEADER_BYTES = 65536
const DEFAULT_COOKIE_SECRET string = "COOKIE_SECRET"

const SERVER_SESSION_ID string = "session_id"

const METHOD_GET string = "GET"
const METHOD_POST string = "POST"

var mStaticDir string
var mViewDir string

var mCfg cfg.Cfg = cfg.Cfg{}

type patternFunc struct {
	Pattern    string
	Methods    []string
	HandleFunc func(*Context)
}

var mListFilter []patternFunc
var mListHandle []patternFunc

var mCookieStore *sessions.CookieStore

func Run() {
	var err error

	mCfg.Load(DEFAULT_SERVER_CONFIG_FILE)

	cfStaticDir := mCfg.Str("Server.StaticDir", DEFAULT_SERVER_STATIC_DIR)
	cfViewDir := mCfg.Str("SServer.ViewDir", DEFAULT_SERVER_VIEW_DIR)

	cfAddr := mCfg.Str("Server.Addr", DEFAULT_SERVER_ADDR)
	cfReadTimeout := mCfg.Int("Server.ReadTimeout", DEFAULT_SERVER_READ_TIMEOUT)
	cfWriteTimeout := mCfg.Int("Server.WriteTimeout", DEFAULT_SERVER_WRITE_TIMEOUT)
	cfMaxHeaderBytes := mCfg.Int("Server.MaxHeaderBytes", DEFAULT_SERVER_MAX_HEADER_BYTES)
	cfCookieSecret := mCfg.Str("Server.CookieSecrect", DEFAULT_COOKIE_SECRET)

	mStaticDir, err = filepath.Abs(cfStaticDir)
	if err != nil {
		log.Fatal(err)
	}
	mViewDir, err = filepath.Abs(cfViewDir)
	if err != nil {
		log.Fatal(err)
	}

	mCookieStore = sessions.NewCookieStore([]byte(cfCookieSecret))

	server := &http.Server{
		Addr:           cfAddr,
		ReadTimeout:    time.Duration(cfReadTimeout) * time.Second,
		WriteTimeout:   time.Duration(cfWriteTimeout) * time.Second,
		MaxHeaderBytes: cfMaxHeaderBytes,
		Handler:        &gfHandler{},
	}

	log.Println("Server start at " + cfAddr)
	log.Fatal(server.ListenAndServe())
	log.Println("Server stopted")
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

type gfHandler struct{}

func (*gfHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.EscapedPath()
	staticFile := mStaticDir + path
	if ext.FileExists(staticFile) && r.Method == METHOD_GET {
		http.ServeFile(w, r, staticFile)
	} else {

		session, err := mCookieStore.Get(r, SERVER_SESSION_ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		r.ParseForm()
		context := Context{
			w:            w,
			r:            r,
			Config:       &mCfg,
			Session:      session,
			UrlPath:      r.URL.Path,
			ViewData:     make(map[string]interface{}),
			Method:       r.Method,
			IsGetMethod:  r.Method == METHOD_GET,
			IsPostMethod: r.Method == METHOD_POST,
			Form:         r.Form,
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
						http.Error(w, "ParseFiles: "+err.Error(), http.StatusInternalServerError)
						return
					}
					err = tem.Execute(w, context.ViewData)
					if err != nil {
						http.Error(w, "Execute: "+err.Error(), http.StatusInternalServerError)
						return
					}
				}
				return
			}
		}

		http.Error(w, "404 - Not Found", http.StatusNotFound)
	}
}
