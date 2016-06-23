package gf

import (
	"html"
	"reflect"
	"strconv"
	"strings"
)

const FORM_TAG = "form"

type Form struct {
	formMap map[string][]string
}

func (this *Form) Exist(key string) bool {
	_, ok := this.formMap[key]
	return ok
}

func (this *Form) IsArray(key string) bool {
	values, ok := this.formMap[key]
	if ok {
		return len(values) > 1
	}
	return false
}

func (this *Form) Array(key string) []string {
	values, ok := this.formMap[key]
	if ok {
		for key, value := range values {
			values[key] = html.EscapeString(value)
		}
		return values
	}
	return nil
}

func (this *Form) ArrayNoEscape(key string) []string {
	values, ok := this.formMap[key]
	if ok {
		return values
	}
	return nil
}

func (this *Form) String(key string) string {
	values, ok := this.formMap[key]
	if ok {
		if len(values) >= 1 {
			return html.EscapeString(strings.Join(values, ","))
		}
	}
	return ""
}

func (this *Form) StringNoEscape(key string) string {
	values, ok := this.formMap[key]
	if ok {
		if len(values) >= 1 {
			return strings.Join(values, ",")
		}
	}
	return ""
}

func (this *Form) Bool(key string) bool {
	value := this.StringNoEscape(key)
	boolValue, _ := strconv.ParseBool(value)
	return boolValue
}

func (this *Form) Int(key string) int {
	value := this.StringNoEscape(key)
	intValue, _ := strconv.ParseInt(value, 10, 64)
	return int(intValue)
}

func (this *Form) Int64(key string) int64 {
	value := this.StringNoEscape(key)
	intValue, _ := strconv.ParseInt(value, 10, 64)
	return int64(intValue)
}

func (this *Form) Int32(key string) int32 {
	value := this.StringNoEscape(key)
	intValue, _ := strconv.ParseInt(value, 10, 32)
	return int32(intValue)
}

func (this *Form) Float32(key string) float32 {
	value := this.StringNoEscape(key)
	floatValue, _ := strconv.ParseFloat(value, 32)
	return float32(floatValue)
}

func (this *Form) Float64(key string) float64 {
	value := this.StringNoEscape(key)
	floatValue, _ := strconv.ParseFloat(value, 64)
	return float64(floatValue)
}

// Read form values and set to a struct
// Ex:
//    Call: ctx.Form.ReadStruct(&formABCVar)
//    Struct define:
//       type FormABC struct {
//             FieldA int `form:"this_is_a"`	// read from input name="this_is_a"
//             FieldB float `this_is_b` 		// read from input name="this_is_b"
//             FieldC string 					// read from input name="FieldC"
//             privateField string				// will not read this field
//             ArrayVar [] `list_abc`			// read string array from input name="list_abc"
//        }
func (this *Form) ReadStruct(obj interface{}) {
	typeOfStringSlice := reflect.TypeOf([]string(nil))

	v := reflect.ValueOf(obj).Elem()
	if v.Kind() != reflect.Struct {
		return  // bail if it's not a struct
	}

	n := v.NumField() // number of fields in struct

	for i := 0; i < n; i = i + 1 {
		if ! v.Field(i).CanSet() {
			continue
		}

		tag := v.Type().Field(i).Tag.Get(FORM_TAG)
		fullTag := string(v.Type().Field(i).Tag)
		name := v.Type().Field(i).Name

		formKey := ""

		if this.Exist(tag) {
			formKey = tag
		} else if this.Exist(fullTag) {
			formKey = fullTag
		} else if this.Exist(name) {
			formKey = name
		} else {
			continue
		}

		f := v.Field(i)
		switch f.Kind() {
		case reflect.String:
			v.Field(i).SetString(this.String(formKey))
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			intValue, _ := strconv.ParseInt(this.String(formKey), 10, 64)
			v.Field(i).SetInt(intValue)
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			uintValue, _ := strconv.ParseUint(this.String(formKey), 10, 64)
			v.Field(i).SetUint(uintValue)
		case reflect.Float64, reflect.Float32:
			floatValue, _ := strconv.ParseFloat(this.String(formKey), 64)
			v.Field(i).SetFloat(floatValue)
		case reflect.Bool:
			boolValue, _ := strconv.ParseBool(this.String(formKey))
			v.Field(i).SetBool(boolValue)
		case reflect.Slice:
			if f.Type() == typeOfStringSlice {
				stringArray := reflect.ValueOf(this.Array(formKey))
				v.Field(i).Set(stringArray)
			}
		default:
		// nothing set so reset to previous
		}
	}
}

