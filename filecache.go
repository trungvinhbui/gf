package gf

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type fileCache struct {
	Name    string
	ModTime time.Time
	Size    int64
	Data    []byte
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
		newFc := fileCache{
			Size:    stat.Size(),
			ModTime: stat.ModTime(),
			Name:    filepath.Base(file),
			Data:    data,
		}

		mFileCacheLock.Lock()
		mFileCacheMap[file] = &newFc
		mFileCacheLock.Unlock()

		return &newFc, nil
	}

	return nil, nil
}
