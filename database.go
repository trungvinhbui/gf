package gf

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/goframework/gf/exterror"
	"log"
	"strconv"
)

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
