package ext

import (
	"reflect"
	"strconv"
)

// Get List Tag of pointer of an struct
// Example: ListTag(&structVariable, "csv")
func ListTagByKey(f interface{}, tagKey string) []string {
	val := reflect.ValueOf(f).Elem()

	listTag := []string{}

	for i := 0; i < val.NumField(); i++ {
		tag := val.Type().Field(i).Tag.Get(tagKey)
		if len(tag) > 0 {
			listTag = append(listTag, tag)
		}
	}

	return listTag
}

// Parse struct value of pointer of an interface
// Example: ListTag(&structVariable, "csv")
func ListInterfaceValueByTag(f interface{}, tagKey string) []interface{} {

	val := reflect.ValueOf(f).Elem()

	listValues := []interface{}{}

	for i := 0; i < val.NumField(); i++ {
		tag := val.Type().Field(i).Tag.Get(tagKey)
		if len(tag) > 0 {
			listValues = append(listValues, val.Field(i).Interface())
		}
	}

	return listValues
}

// Parse struct value of pointer of an interface
// Example: ListTag(&structVariable, "csv")
func ListStringValueByTag(f interface{}, tagKey string) []string {
	val := reflect.ValueOf(f).Elem()

	listValues := []string{}

	for i := 0; i < val.NumField(); i++ {
		tag := val.Type().Field(i).Tag.Get(tagKey)
		if len(tag) > 0 {
			v := ""
			switch val.Field(i).Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				v = strconv.FormatInt(val.Field(i).Int(), 10)
			default:
				v = val.Field(i).String()
			}
			listValues = append(listValues, v)
		}
	}

	return listValues
}
