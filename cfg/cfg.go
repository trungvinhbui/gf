package cfg

import (
	"bufio"
	"github.com/goframework/gf/ext"
	"log"
	"os"
	"strconv"
	"strings"
)

type Cfg struct {
	Data    map[string]string
	ArrData map[string][]string
}

func (this *Cfg) Str(key string, defaultValue string) string {
	if v, ok := this.Data[key]; ok {
		return v
	}
	return defaultValue
}

func (this *Cfg) StrOrEmpty(key string) string {
	return this.Str(key, "")
}

func (this *Cfg) Int(key string, defaultValue int) int {
	if v, ok := this.Data[key]; ok {
		if num, err := strconv.Atoi(v); err == nil {
			return num
		}
	}
	return defaultValue
}

func (this *Cfg) IntOrZero(key string) int {
	return this.Int(key, 0)
}

func (this *Cfg) Bool(key string, defaultValue bool) bool {
	if v, ok := this.Data[key]; ok {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return defaultValue
}

func (this *Cfg) BoolOrFalse(key string) bool {
	return this.Bool(key, false)
}

func (this *Cfg) Int64(key string, defaultValue int64) int64 {
	if v, ok := this.Data[key]; ok {
		if num, err := strconv.ParseInt(v, 10, 64); err == nil {
			return num
		}
	}
	return defaultValue
}

func (this *Cfg) Int64OrZero(key string) int64 {
	return this.Int64(key, 0)
}

func (this *Cfg) List(key string) []string {
	if v, ok := this.ArrData[key]; ok {
		return v
	}
	return nil
}

func (this *Cfg) Load(file string) {

	//Reset data
	this.Data = map[string]string{}
	this.ArrData = map[string][]string{}

	// Open an input file, exit on error.
	inputFile, err := os.Open(file)
	if err != nil {
		log.Println("Error opening config file:", err)
		return
	}

	// Closes the file when we leave the scope of the current function,
	// this makes sure we never forget to close the file if the
	// function can exit in multiple places.
	defer inputFile.Close()

	scanner := bufio.NewScanner(inputFile)

	// scanner.Scan() advances to the next token returning false if an error was encountered
	for scanner.Scan() {
		line := scanner.Text()

		eqIndex := strings.Index(line, "=")
		if eqIndex > 0 {

			key := strings.Trim(line[:eqIndex], " 	　")
			if key[0] != '#' {
				value := strings.Trim(line[eqIndex+1:], " 　")
				value = ext.ReplaceEnv(value)

				if strings.HasSuffix(key, "[]") {
					key = strings.TrimRight(key, "[]")
					this.ArrData[key] = append(this.ArrData[key], value)
				} else {
					this.Data[key] = value
				}
			}
		}
	}

	// When finished scanning if any error other than io.EOF occurred
	// it will be returned by scanner.Err().
	if err := scanner.Err(); err != nil {
		log.Fatal(scanner.Err())
	}
}
