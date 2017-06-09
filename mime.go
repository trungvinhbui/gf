package gf

import (
	"mime"
)

var builtinTypesLower = map[string]string{
	".css":  "text/css",
	".csv":  "text/csv",
	".gif":  "image/gif",
	".htm":  "text/html",
	".html": "text/html",
	".ico":  "image/vnd.microsoft.icon",
	".jpg":  "image/jpeg",
	".js":   "application/javascript",
	".pdf":  "application/pdf",
	".png":  "image/png",
	".svg":  "image/svg+xml",
	".xml":  "text/xml",
}

func init() {
	for k,v := range builtinTypesLower {
		mime.AddExtensionType(k, v)
	}
}
