package gf

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/goframework/gf/exterror"
	"log"
	"strconv"
	"reflect"
	"fmt"
)

const SQL_TAG = "sql"

type sqlDBFactory struct {
	Driver   string
	Host     string
	Port     int
	User     string
	Pwd      string
	Database string

	IsEnable bool
}

func (this *sqlDBFactory) Check() error {
	this.IsEnable = (this.Driver != "")

	if this.IsEnable {
		db, err := sql.Open(this.Driver,
			this.User+":"+this.Pwd+"@tcp("+this.Host+":"+strconv.Itoa(this.Port)+")/"+this.Database)
		if db != nil {
			db.Close()
		}

		return err
	}

	return nil
}

func (this *sqlDBFactory) NewConnect() *sql.DB {
	db, err := sql.Open(this.Driver,
		this.User+":"+this.Pwd+"@tcp("+this.Host+":"+strconv.Itoa(this.Port)+")/"+this.Database)
	if err != nil {
		log.Println(exterror.WrapExtError(err))
		return nil
	}
	return db
}

func SqlScanStruct(rows *sql.Rows, outputStruct interface{}) error {
	v := reflect.ValueOf(outputStruct).Elem()
	if v.Kind() != reflect.Struct {
		return nil // bail if it's not a struct
	}

	cols, err := rows.Columns()
	if err != nil {
		return err
	}

	countColumn := len(cols)
	values := make([]interface{}, countColumn)
	valuePtrs := make([]interface{}, countColumn)

	for i, _ := range valuePtrs {
		valuePtrs[i] = &values[i]
	}

	if err := rows.Scan(valuePtrs...); err != nil {
		return err
	}

	valueMap := make(map[string]interface{})
	for id, colName := range cols {
		val := values[id]
		if val != nil {
			if b, ok := val.([]byte); ok {
				valueMap[colName] = string(b)
			} else {
				valueMap[colName] = val
			}
		} else {
			valueMap[colName] = nil
		}
	}

	n := v.NumField() // number of fields in struct

	for i := 0; i < n; i = i + 1 {
		if ! v.Field(i).CanSet() {
			continue
		}

		var fieldValue interface{}

		if fV, ok := valueMap[v.Type().Field(i).Tag.Get(SQL_TAG)]; ok {
			fieldValue = fV
		} else if fV, ok := valueMap[string(v.Type().Field(i).Tag)]; ok {
			fieldValue = fV
		} else if fV, ok := valueMap[v.Type().Field(i).Name]; ok {
			fieldValue = fV
		} else {
			continue
		}

		if fieldValue == nil {
			continue
		}

		f := v.Field(i)
		switch f.Kind() {
		case reflect.String:
			v.Field(i).SetString(fmt.Sprintf("%v",fieldValue))
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			intValue, _ := strconv.ParseInt(fmt.Sprintf("%v",fieldValue), 10, 64)
			v.Field(i).SetInt(intValue)
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			uintValue, _ := strconv.ParseUint(fmt.Sprintf("%v",fieldValue), 10, 64)
			v.Field(i).SetUint(uintValue)
		case reflect.Float64, reflect.Float32:
			floatValue, _ := strconv.ParseFloat(fmt.Sprintf("%v",fieldValue), 64)
			v.Field(i).SetFloat(floatValue)
		case reflect.Bool:
			boolValue, _ := strconv.ParseBool(fmt.Sprintf("%v",fieldValue))
			v.Field(i).SetBool(boolValue)
		case reflect.Ptr:
			switch f.Type() {
			case reflect.PtrTo(reflect.TypeOf(string(""))):
				svalue := fmt.Sprintf("%v",fieldValue)
				v.Field(i).Set(reflect.ValueOf(&svalue))
			case reflect.PtrTo(reflect.TypeOf(int(0))):
				int64Value, _ := strconv.ParseInt(fmt.Sprintf("%v",fieldValue), 10, 64)
				intValue := int(int64Value)
				v.Field(i).Set(reflect.ValueOf(&intValue))
			case reflect.PtrTo(reflect.TypeOf(int8(0))):
				int64Value, _ := strconv.ParseInt(fmt.Sprintf("%v",fieldValue), 10, 64)
				int8Value := int8(int64Value)
				v.Field(i).Set(reflect.ValueOf(&int8Value))
			case reflect.PtrTo(reflect.TypeOf(int16(0))):
				int64Value, _ := strconv.ParseInt(fmt.Sprintf("%v",fieldValue), 10, 64)
				int16Value := int16(int64Value)
				v.Field(i).Set(reflect.ValueOf(&int16Value))
			case reflect.PtrTo(reflect.TypeOf(int32(0))):
				int64Value, _ := strconv.ParseInt(fmt.Sprintf("%v",fieldValue), 10, 64)
				int32Value := int32(int64Value)
				v.Field(i).Set(reflect.ValueOf(&int32Value))
			case reflect.PtrTo(reflect.TypeOf(int64(0))):
				int64Value, _ := strconv.ParseInt(fmt.Sprintf("%v",fieldValue), 10, 64)
				v.Field(i).Set(reflect.ValueOf(&int64Value))
			case reflect.PtrTo(reflect.TypeOf(uint(0))):
				uint64Value, _ := strconv.ParseUint(fmt.Sprintf("%v",fieldValue), 10, 64)
				uintValue := uint(uint64Value)
				v.Field(i).Set(reflect.ValueOf(&uintValue))
			case reflect.PtrTo(reflect.TypeOf(uint8(0))):
				uint64Value, _ := strconv.ParseUint(fmt.Sprintf("%v",fieldValue), 10, 64)
				uint8Value := uint8(uint64Value)
				v.Field(i).Set(reflect.ValueOf(&uint8Value))
			case reflect.PtrTo(reflect.TypeOf(uint16(0))):
				uint64Value, _ := strconv.ParseUint(fmt.Sprintf("%v",fieldValue), 10, 64)
				uint16Value := uint16(uint64Value)
				v.Field(i).Set(reflect.ValueOf(&uint16Value))
			case reflect.PtrTo(reflect.TypeOf(uint32(0))):
				uint64Value, _ := strconv.ParseUint(fmt.Sprintf("%v",fieldValue), 10, 64)
				uint32Value := uint32(uint64Value)
				v.Field(i).Set(reflect.ValueOf(&uint32Value))
			case reflect.PtrTo(reflect.TypeOf(uint64(0))):
				uint64Value, _ := strconv.ParseUint(fmt.Sprintf("%v",fieldValue), 10, 64)
				v.Field(i).Set(reflect.ValueOf(&uint64Value))
			case reflect.PtrTo(reflect.TypeOf(float32(0))):
				float64Value, _ := strconv.ParseFloat(fmt.Sprintf("%v",fieldValue), 64)
				float32Value := float32(float64Value)
				v.Field(i).Set(reflect.ValueOf(&float32Value))
			case reflect.PtrTo(reflect.TypeOf(float64(0))):
				float64Value, _ := strconv.ParseFloat(fmt.Sprintf("%v",fieldValue), 64)
				v.Field(i).Set(reflect.ValueOf(&float64Value))
			case reflect.PtrTo(reflect.TypeOf(bool(false))):
				boolValue, _ := strconv.ParseBool(fmt.Sprintf("%v",fieldValue))
				v.Field(i).Set(reflect.ValueOf(&boolValue))
			}
		default:
		}
	}

	return nil
}