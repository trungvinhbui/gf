package db

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/goframework/gf/exterror"
	"log"
	"fmt"
)

const SQL_TAG = "sql"
const (
	DRIVER_MYSQL = "mysql"
)

const (
	//Variable order: User, Pwd, Server, Database

	FORMART_CON_STR_MYSQL = "%[1]s:%[2]s@(%[3]s)/%[4]s"
)

// map driver name and connection string
var _DRIVERS = map[string]string{
	DRIVER_MYSQL:FORMART_CON_STR_MYSQL,
}

type SqlDBFactory struct {
	Driver   string // Supported driver: "mysql"
	Server   string // host[:port]
	User     string // login name
	Pwd      string // password
	Database string // database / schema

	IsEnable bool
}

func (this *SqlDBFactory) Check() error {
	conFormat, driverOk := _DRIVERS[this.Driver]
	this.IsEnable = driverOk

	if this.IsEnable {
		db, err := sql.Open(this.Driver,
			fmt.Sprintf(conFormat, this.User, this.Pwd, this.Server, this.Database))
		if db != nil {
			db.Close()
		}

		return err
	}

	return nil
}

// If no error, return *sql.DB, do not forget to defer db.Close()
func (this *SqlDBFactory) NewConnect() *sql.DB {
	conFormat, driverOk := _DRIVERS[this.Driver]
	if !driverOk {
		return nil
	}

	db, err := sql.Open(this.Driver,
		fmt.Sprintf(conFormat, this.User, this.Pwd, this.Server, this.Database))
	if err != nil {
		log.Println(exterror.WrapExtError(err))
		return nil
	}
	return db
}
