package gf

import (
	"bytes"
	"compress/gzip"
	"github.com/goframework/gf/buffer"
	"github.com/goframework/gf/fsgzip"
	"github.com/tdewolff/minify"
	"github.com/tdewolff/minify/css"
	"github.com/tdewolff/minify/html"
	"github.com/tdewolff/minify/js"
	"github.com/tdewolff/minify/json"
	"github.com/tdewolff/minify/svg"
	"github.com/tdewolff/minify/xml"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var _MINIFY_ENABLE_EXT = map[string]minify.MinifierFunc{
	".css":  css.Minify,
	".htm":  html.Minify,
	".html": html.Minify,
	".js":   js.Minify,
	".json": json.Minify,
	".svg":  svg.Minify,
	".xml":  xml.Minify,
}

type fileCache struct {
	Name     string
	ModTime  time.Time
	Size     int64
	Data     []byte
	GzipData []byte
}

var mFileCacheMaxSize = int64(DEFAULT_SERVER_STATIC_MAX_CACHE_FZ)
var mFileCacheLock = sync.Mutex{}
var mFileCacheMap = map[string]*fileCache{}

func getFileCache(file string) (*fileCache, error) {
	stat, err := os.Stat(file)
	if err != nil {
		return nil, err
	}

	mFileCacheLock.Lock()
	fc, cacheExist := mFileCacheMap[file]
	mFileCacheLock.Unlock()

	if cacheExist {
		if fc.ModTime.Equal(stat.ModTime()) {
			return fc, nil
		}
	}

	if stat.Size() <= mFileCacheMaxSize {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			return nil, err
		}

		if mEnableMinify {
			fileExt := filepath.Ext(file)
			if minifyFunc, exist := _MINIFY_ENABLE_EXT[fileExt]; exist && !strings.HasSuffix(file, ".min"+fileExt) {
				m := minify.New()
				m.AddFunc(fileExt, minifyFunc)
				miniData, err := m.Bytes(fileExt, data)
				if err == nil {
					data = miniData
				} else {
					log.Printf("Minify error at [%v]: %v", file, err)
				}
			}
		}

		var gzipData []byte = nil
		if mEnableGzip && isGzipEnable(file) {
			gzBuf := bytes.Buffer{}
			wt := gzip.NewWriter(&gzBuf)
			_, err := wt.Write(data)
			if err != nil {
				return nil, err
			}
			err = wt.Close()
			if err != nil {
				return nil, err
			}

			gzipData = gzBuf.Bytes()
		}
		newFc := fileCache{
			Size:     stat.Size(),
			ModTime:  stat.ModTime(),
			Name:     filepath.Base(file),
			Data:     data,
			GzipData: gzipData,
		}

		mFileCacheLock.Lock()
		mFileCacheMap[file] = &newFc
		mFileCacheLock.Unlock()

		return &newFc, nil
	}

	return nil, nil
}

func serveCacheFile(w http.ResponseWriter, r *http.Request, fc *fileCache) {
	if mEnableGzip && fc.GzipData != nil {
		fsgzip.ServeContent(w, r, fc.Name, fc.ModTime, buffer.NewReadSeekBuffer(fc.Data), fc.GzipData)
	} else {
		http.ServeContent(w, r, fc.Name, fc.ModTime, buffer.NewReadSeekBuffer(fc.Data))
	}
}
