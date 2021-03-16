package pgxtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"github.com/danvixent/pgxtls/config"
	"github.com/jackc/pgx/v4"
	pool "github.com/jackc/pgx/v4/pgxpool"
)

type AfterConnectFunc func(context.Context, *pgx.Conn) error

// NewFromCfgMap Returns a new database initialized with credentials from config
func NewFromCfgMap(ctx context.Context, config *config.ConfigMap, fn AfterConnectFunc) (*pool.Pool, error) {

	const format = "postgres://%s:%s@%s:%d/%s?sslmode=%s&pool_max_conns=%d"
	uri := fmt.Sprintf(
		format, config.DbUser,
		config.Password, config.DbHost,
		config.DbPort, config.DbName,
		config.SSLMode, config.MaxConns,
	)

	cfg, err := pool.ParseConfig(uri)
	if err != nil {
		return nil, err
	}

	cfg.AfterConnect = fn
	cfg.ConnConfig.DialFunc = func(ctx context.Context, host string, addr string) (net.Conn, error) {
		return net.Dial(host, addr)
	}

	cfg.ConnConfig.PreferSimpleProtocol = true
	cfg.ConnConfig.ConnectTimeout = time.Minute

	var xPool *x509.CertPool

	if config.SSLCAFile == "" {
		xPool, err = x509.SystemCertPool()
		return nil, fmt.Errorf("unable to retrieve system cert pool: %v", err)
	} else {
		CAcert, err := ioutil.ReadFile(config.SSLCAFile)
		if err != nil {
			return nil, err
		}

		xPool = x509.NewCertPool()
		if !xPool.AppendCertsFromPEM(CAcert) {
			return nil, errors.New("can't add ca cert to cert pool")
		}

	}

	cert, err := withPassphrase(config.SSLCertFile, config.SSLKeyFile, []byte(config.SSLKeyFilePassPhrase))
	if err != nil {
		return nil, err
	}

	cfg.ConnConfig.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{*cert},
		RootCAs:      xPool,
	}

	if config.SSLHostname != "" {
		cfg.ConnConfig.TLSConfig.ServerName = config.SSLHostname
	} else {
		cfg.ConnConfig.TLSConfig.InsecureSkipVerify = true
	}

	pool, err := pool.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return pool, nil
}

// withPassphrase takes .key and .crt file paths
// decodes the .key file with the give passphrase
// and constructs a tls.Certificate with the .crt
// file and the decoded .key file
func withPassphrase(pathToCert string, pathToKey string, password []byte) (*tls.Certificate, error) {

	keyFile, err := ioutil.ReadFile(pathToKey)
	if err != nil {
		return nil, err
	}

	certFile, err := ioutil.ReadFile(pathToCert)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyFile)

	// Decrypt key
	keyDER, err := x509.DecryptPEMBlock(keyBlock, password)
	if err != nil {
		return nil, err
	}

	keyBlock.Bytes = keyDER // Update keyBlock with the plaintext bytes
	keyBlock.Headers = nil  //clear the now obsolete headers.

	// Turn the key back into PEM format so we can leverage tls.X509KeyPair,
	// which will deal with the intricacies of error handling, different key
	// types, certificate chains, etc.
	cert, err := tls.X509KeyPair(certFile, pem.EncodeToMemory(keyBlock))
	if err != nil {
		return nil, err
	}
	return &cert, nil
}
