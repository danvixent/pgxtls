package config

import (
	"encoding/json"
	"errors"
	"os"
	"strconv"

	"github.com/asaskevich/govalidator"
)

//ConfigMap holds configuration data
type ConfigMap struct {
	DbName               string `validate:"required"` // name of database to connect to
	DbHost               string `validate:"required"` // database server hostname
	DbUser               string `validate:"required"` // database user to connect as
	Password             string `validate:"required"` // password of database user
	SSLMode              string `validate:"required"` // ssl mode to use when connecting to database
	SSLCertFile          string `validate:"required"` // .crt file to use for ssl
	SSLKeyFile           string `validate:"required"` // .key file to use for ssl
	SSLKeyFilePassPhrase string `validate:"required"` // passphrase for .key file
	SSLCAFile            string `validate:"required"` // CA authority to trust
	SSLHostname          string `validate:"required"` // expected hostname on certificate the database server will present
	ServerPort           uint16 `validate:"required"` // port on which to serve the gRPC server on
	DbPort               uint16 `validate:"required"` // port on which to connect to database server on
	MaxConns             uint8  `validate:"required"` // max connections to the database
}

//FromFile returns a New ConfigMap with values parsed from file
func FromFile(file string) (*ConfigMap, error) {
	return parse(&file)
}

func parse(cfile *string) (*ConfigMap, error) {
	file, err := os.Open(*cfile)
	if err != nil {
		return nil, err
	}
	config := &ConfigMap{}

	if err := json.NewDecoder(file).Decode(config); err != nil {
		return nil, errors.New("can't parse config file: " + err.Error())
	}

	if err = config.validate(); err != nil {
		return nil, err
	}

	return config, nil
}

//FromEnv fetches configuration data from environment variables
func FromEnv() (*ConfigMap, error) {
	dbport, err := strconv.Atoi(os.Getenv("DB_PORT"))
	if err != nil {
		return nil, err
	}

	srvPort, err := strconv.Atoi(os.Getenv("SERVER_PORT"))
	if err != nil {
		return nil, err
	}

	maxConns, err := strconv.Atoi(os.Getenv("MAX_CONNS"))
	if err != nil {
		return nil, err
	}

	config := &ConfigMap{
		DbName:     os.Getenv("DB_NAME"),
		DbHost:     os.Getenv("DB_HOST"),
		DbUser:     os.Getenv("DB_USER"),
		Password:   os.Getenv("DB_PASSWORD"),
		SSLMode:    os.Getenv("SSL_MODE"),
		ServerPort: uint16(srvPort),
		DbPort:     uint16(dbport),
		MaxConns:   uint8(maxConns),
	}

	if err := config.validate(); err != nil {
		return nil, err
	}
	return config, nil
}

func (c *ConfigMap) validate() error {
	_, err := govalidator.ValidateStruct(c)
	return err
}
