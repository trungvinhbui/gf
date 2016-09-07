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
		case reflect.Ptr:
			switch f.Type() {
				case reflect.PtrTo(reflect.TypeOf(string(""))):
					svalue := this.String(formKey)
					v.Field(i).Set(reflect.ValueOf(&svalue))
				case reflect.PtrTo(reflect.TypeOf(int(0))):
					int64Value, _ := strconv.ParseInt(this.String(formKey), 10, 64)
					intValue := int(int64Value)
					v.Field(i).Set(reflect.ValueOf(&intValue))
				case reflect.PtrTo(reflect.TypeOf(int8(0))):
					int64Value, _ := strconv.ParseInt(this.String(formKey), 10, 64)
					int8Value := int8(int64Value)
					v.Field(i).Set(reflect.ValueOf(&int8Value))
				case reflect.PtrTo(reflect.TypeOf(int16(0))):
					int64Value, _ := strconv.ParseInt(this.String(formKey), 10, 64)
					int16Value := int16(int64Value)
					v.Field(i).Set(reflect.ValueOf(&int16Value))
				case reflect.PtrTo(reflect.TypeOf(int32(0))):
					int64Value, _ := strconv.ParseInt(this.String(formKey), 10, 64)
					int32Value := int32(int64Value)
					v.Field(i).Set(reflect.ValueOf(&int32Value))
				case reflect.PtrTo(reflect.TypeOf(int64(0))):
					int64Value, _ := strconv.ParseInt(this.String(formKey), 10, 64)
					v.Field(i).Set(reflect.ValueOf(&int64Value))
				case reflect.PtrTo(reflect.TypeOf(uint(0))):
					uint64Value, _ := strconv.ParseUint(this.String(formKey), 10, 64)
					uintValue := uint(uint64Value)
					v.Field(i).Set(reflect.ValueOf(&uintValue))
				case reflect.PtrTo(reflect.TypeOf(uint8(0))):
					uint64Value, _ := strconv.ParseUint(this.String(formKey), 10, 64)
					uint8Value := uint8(uint64Value)
					v.Field(i).Set(reflect.ValueOf(&uint8Value))
				case reflect.PtrTo(reflect.TypeOf(uint16(0))):
					uint64Value, _ := strconv.ParseUint(this.String(formKey), 10, 64)
					uint16Value := uint16(uint64Value)
					v.Field(i).Set(reflect.ValueOf(&uint16Value))
				case reflect.PtrTo(reflect.TypeOf(uint32(0))):
					uint64Value, _ := strconv.ParseUint(this.String(formKey), 10, 64)
					uint32Value := uint32(uint64Value)
					v.Field(i).Set(reflect.ValueOf(&uint32Value))
				case reflect.PtrTo(reflect.TypeOf(uint64(0))):
					uint64Value, _ := strconv.ParseUint(this.String(formKey), 10, 64)
					v.Field(i).Set(reflect.ValueOf(&uint64Value))
				case reflect.PtrTo(reflect.TypeOf(float32(0))):
					float64Value, _ := strconv.ParseFloat(this.String(formKey), 64)
					float32Value := float32(float64Value)
					v.Field(i).Set(reflect.ValueOf(&float32Value))
				case reflect.PtrTo(reflect.TypeOf(float64(0))):
					float64Value, _ := strconv.ParseFloat(this.String(formKey), 64)
					v.Field(i).Set(reflect.ValueOf(&float64Value))
				case reflect.PtrTo(reflect.TypeOf(bool(false))):
					boolValue, _ := strconv.ParseBool(this.String(formKey))
					v.Field(i).Set(reflect.ValueOf(&boolValue))
			}
		default:
		// nothing set so reset to previous
		}
	}
}

