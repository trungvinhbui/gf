package gf

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

var mFlushMapTimeout = false
var mLocker = sync.Mutex{}
var mMapIPRequest1 = map[string]int{}
var mMapIPRequest2 = map[string]int{}
var mIPRequestLimit = DEFAULT_SERVER_IP_REQUEST_LIMIT

func init() {
	go func() {
		for {
			time.Sleep(2 * time.Second)
			mFlushMapTimeout = true
		}
	}()
}

func overIPLimit(w http.ResponseWriter, r *http.Request) bool {
	mLocker.Lock()
	defer mLocker.Unlock()

	if mFlushMapTimeout {
		if len(mMapIPRequest1) > 0 || len(mMapIPRequest2) > 0 {
			mMapIPRequest2 = mMapIPRequest1
			mMapIPRequest1 = map[string]int{}
		}
		mFlushMapTimeout = false
	}

	addr := r.RemoteAddr

	if colonId := strings.LastIndex(addr, ":"); colonId > 0 {
		ip := addr[:colonId]
		mMapIPRequest1[ip]++

		if mMapIPRequest1[ip] > mIPRequestLimit {
			return true
		}
	}

	return false
}
