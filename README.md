# Golang simple framework

## Start using it
1. Download and install it:
  
  ```sh
$ go get github.com/goframework/gf
```
2. Create server.cfg
  
  ```INI
Server.Addr 			= :8016
Server.ReadTimeout		= 120
Server.WriteTimeout		= 120
Server.MaxHeaderBytes	= 65536
Server.StaticDir		= ./static
Server.ViewDir			= ./view
Server.CookieSecrect	= Your cookie secrect (any string)
```
3. Create view/helloworld.html
  
  ```html
<!DOCTYPE html>
<html>
<head>
<title>Hello world from GF</title>
</head>
<body>
<p>Hello {{.name}} !</p>
</body>
</html>
```

4. Create main.go
  
  ```go
package main

import (
	"github.com/goframework/gf"
)

func main() {
	gf.HandleGet("/", func(ctx *gf.Context) {
		ctx.View = "helloworld.html"
	})
	
	gf.HandleGet("/{name}", func(ctx *gf.Context) {
		ctx.ViewData["name"] = ctx.RouteVars["name"]
		ctx.View = "helloworld.html"
	})
}
```

5. Build, run, then open browser and go to address:
  
  [http://localhost:8016](http://localhost:8016)
  
  [http://localhost:8016/your_name](http://localhost:8016/your_name)

