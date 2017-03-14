package exterror

import (
	"fmt"
	"runtime"
	"strings"
)

var filePathSpliter string = ""

type ExtError struct {
	error
	traceStack []string
}

func SetFilePathSpliter(spliter string) {
	filePathSpliter = spliter
}

func (this ExtError) Error() string {
	es := fmt.Sprintf("[ERROR] %v \r\n\t%v", this.error, strings.Join(this.traceStack, "\r\n\t"))
	return es
}

func TraceError(err error) error {
	return WrapExtError(err)
}

func WrapExtError(err error) error {
	if err == nil {
		return nil
	}

	var ee ExtError

	switch err.(type) {
	case ExtError:
		ee = err.(ExtError)
	default:
		ee = ExtError{err, []string{}}
	}

	pc, fn, line, _ := runtime.Caller(1)
	if filePathSpliter != "" {
		fns := strings.SplitN(fn, filePathSpliter, 2)
		if len(fns) > 1 {
			fn = fns[1]
		}
	}

	funcName := func() string {
		fnPart := strings.Split(runtime.FuncForPC(pc).Name(), "/")
		return fnPart[len(fnPart)-1]
	}()

	ee.traceStack = append(ee.traceStack, fmt.Sprintf("[%s:%d]    %s", fn, line, funcName))

	return ee
}
