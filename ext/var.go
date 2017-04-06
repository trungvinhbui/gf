package ext

import (
	"regexp"
	"strconv"
	"strings"
)

type Var string

func (v *Var) String() string {
	return string(*v)
}

func (v *Var) Float() float32 {
	floatValue, _ := strconv.ParseFloat(string(*v), 32)
	return float32(floatValue)
}

func (v *Var) Float64() float64 {
	floatValue, _ := strconv.ParseFloat(string(*v), 32)
	return floatValue
}

func (v *Var) Int() int {
	intValue, _ := strconv.ParseInt(string(*v), 10, 32)
	return int(intValue)
}

func (v *Var) Int64() int64 {
	intValue, _ := strconv.ParseInt(string(*v), 10, 64)
	return intValue
}

func (v *Var) UInt() uint {
	uIntValue, _ := strconv.ParseUint(string(*v), 10, 32)
	return uint(uIntValue)
}

func (v *Var) UInt64() uint64 {
	uIntValue, _ := strconv.ParseUint(string(*v), 10, 64)
	return uIntValue
}

func (v *Var) Bool() bool {
	boolValue, _ := strconv.ParseBool(string(*v))
	return boolValue
}

// Match variables string
// Example:
//            /path/to/{name}
//            /path/to/{name:pattern}
func VarMatch(pattern string, input string) (map[string]Var, bool) {

	lenP := len(pattern)
	lenI := len(input)

	i := 0
	p := 0

	vars := map[string]Var{}

	for i < lenI && p < lenP {
		if pattern[p] == '{' {
			pe := -1
			subPattern := pattern[p:]
			countBracket := 0
			for i := 0; i < len(subPattern); i++ {
				if subPattern[i] == '{' {
					countBracket++
				} else if subPattern[i] == '}' {
					countBracket--
					if countBracket == 0 {
						pe = i
						break
					}
				}
			}

			if pe <= 1 {
				return nil, false
			}
			varName := pattern[p+1 : p+pe]

			ie := strings.Index(input[i:], "/")
			if ie < 0 {
				ie = len(input[i:])
			}

			varVal := input[i : i+ie]

			iRegex := strings.Index(varName, ":")
			if iRegex >= 0 {
				varPattern := varName[iRegex+1:]
				varName = varName[:iRegex]

				if matched, _ := regexp.MatchString(varPattern, varVal); !matched {
					return nil, false
				}
			}

			vars[varName] = Var(varVal)

			p = p + pe + 1
			i = i + ie

		} else {
			if pattern[p] != input[i] {
				return nil, false
			}
			p++
			i++
		}
	}

	if i < lenI || p < lenP {
		return nil, false
	}

	return vars, true
}
