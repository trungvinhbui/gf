package exterror

import (
	"fmt"
	"runtime"
	"strings"
)

var filePathSpliter string = ""

type ExtError struct {
	error
	errorString string
}

func SetFilePathSpliter(spliter string) {
	filePathSpliter = spliter
}

func (this ExtError) Error() string {
	return this.errorString
}

func WrapExtError(err error) error {
	if err == nil {
		return nil
	}

	switch err.(type) {
	case ExtError:
		return err
	default:
		pc, fn, line, _ := runtime.Caller(1)
		if filePathSpliter != "" {
			fns := strings.SplitN(fn, filePathSpliter, 2)
			if len(fns) > 1 {
				fn = fns[1]
			}
		}
		info := fmt.Sprintf("[ERROR] %v \r\nAt %s [%s:%d]", err, runtime.FuncForPC(pc).Name(), fn, line)
		extError := ExtError{err, info}
		return extError
	}
}
