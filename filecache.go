package gf

import (
	"bytes"
	"compress/gzip"
	"github.com/goframework/gf/buffer"
	"github.com/goframework/gf/fsgzip"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

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
