package internal

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/ThalesIgnite/crypto11"
	toml "github.com/pelletier/go-toml"
)

var NotModifiedError = errors.New("Config unchanged on server")

// Functions to be called when the daemon is initialized
var initFunctions = map[string]func(app *App) error{}

type CryptoHandler interface {
	Decrypt(value string) ([]byte, error)
}

type App struct {
	Crypto          CryptoHandler
	EncryptedConfig string
	SecretsDir      string

	client    *http.Client
	configUrl string
}

func loadCA(sota_config string, sota *toml.Tree) []byte {
	source := sota.GetDefault("tls.ca_source", "file").(string)
	if source != "file" {
		fmt.Println("ERROR - unsupported ca_source in sota.toml", source)
		os.Exit(1)
	}

	caFile := sota.GetDefault("import.tls_clientcert_path", filepath.Join(sota_config, "root.crt")).(string)
	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatal(err)
	}
	return caCert
}

func tomlGetString(tree *toml.Tree, key string) string {
	val := tree.GetDefault(key, "").(string)
	if len(val) == 0 {
		fmt.Println("ERROR: Missing", key, "in sota.toml")
		os.Exit(1)
	}
	return val
}

func loadCertLocal(sota_config string, sota *toml.Tree) tls.Certificate {
	certFile := tomlGetString(sota, "import.tls_clientcert_path")
	keyFile := tomlGetString(sota, "import.tls_pkey_path")
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal(err)
	}
	return cert
}

func idToBytes(id string) []byte {
	bytes := []byte(id)
	for idx, char := range bytes {
		bytes[idx] = char - byte('0')
	}
	return bytes
}

func loadCertPkcs11(sota *toml.Tree) tls.Certificate {
	module := tomlGetString(sota, "p11.modules")
	pin := tomlGetString(sota, "p11.pass")
	pkeyId := tomlGetString(sota, "p11.tls_pkey_id")
	certId := tomlGetString(sota, "p11.tls_clientcert_id")

	cfg := crypto11.Config{
		Path:       module,
		TokenLabel: "aktualizr",
		Pin:        pin,
	}

	ctx, err := crypto11.Configure(&cfg)
	if err != nil {
		log.Fatal(err)
	}

	kp, err := ctx.FindKeyPair(idToBytes(pkeyId), nil)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := ctx.FindCertificate(idToBytes(certId), nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	return tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  kp,
	}
}

func loadCert(sota_config string, sota *toml.Tree) tls.Certificate {
	source := sota.GetDefault("tls.pkey_source", "file").(string)
	if source == "file" {
		return loadCertLocal(sota_config, sota)
	} else if source == "pkcs11" {
		return loadCertPkcs11(sota)
	}
	fmt.Println("Invalide tls.pkey_source", source)
	os.Exit(1)
	return tls.Certificate{} // to make compiler happy
}

func createClient(sota_config string) (*http.Client, CryptoHandler) {
	sota, err := toml.LoadFile(filepath.Join(sota_config, "sota.toml"))
	if err != nil {
		fmt.Println("ERROR - unable to decode sota.toml:", err)
		os.Exit(1)
	}

	caCert := loadCA(sota_config, sota)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{loadCert(sota_config, sota)},
		RootCAs:      caCertPool,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Timeout: time.Second * 30, Transport: transport}

	if handler := NewEciesHandler(tlsConfig.Certificates[0].PrivateKey); handler != nil {
		return client, handler
	}
	panic("Unsupported private key")
}

func NewApp(sota_config, secrets_dir string, testing bool) (*App, error) {
	var client *http.Client = nil
	var handler CryptoHandler
	if testing {
		path := filepath.Join(sota_config, "pkey.pem")
		pkey_pem, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("Unable to read private key: %v", err)
		}

		block, _ := pem.Decode(pkey_pem)
		if block == nil {
			return nil, fmt.Errorf("Unable to decode private key(%s): %v", path, err)
		}

		p, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Unable to parse private key(%s): %v", path, err)
		}
		handler = NewEciesHandler(p)
	} else {
		client, handler = createClient(sota_config)
	}

	url := os.Getenv("CONFIG_URL")
	if len(url) == 0 {
		url = "https://ota-lite.foundries.io:8443/config"
	}

	app := App{
		Crypto:          handler,
		EncryptedConfig: filepath.Join(sota_config, "config.encrypted"),
		SecretsDir:      secrets_dir,
		client:          client,
		configUrl:       url,
	}

	return &app, nil
}

// Do an atomic update of the file if needed
func updateSecret(secretFile string, newContent []byte) (bool, error) {
	curContent, err := ioutil.ReadFile(secretFile)
	if err == nil && bytes.Equal(newContent, curContent) {
		return false, nil
	}
	tmp := secretFile + ".tmp"
	if err := ioutil.WriteFile(tmp, newContent, 0640); err != nil {
		return true, fmt.Errorf("Unable to create %s: %v", tmp, err)
	}
	if err := os.Rename(tmp, secretFile); err != nil {
		return true, fmt.Errorf("Unable to update secret: %s - %w", secretFile, err)
	}
	return true, nil
}

func (a *App) Extract() error {
	if _, err := os.Stat(a.SecretsDir); err != nil {
		return err
	}
	config, err := Unmarshall(a.Crypto, a.EncryptedConfig)
	if err != nil {
		return err
	}

	for fname, cfgFile := range config {
		log.Printf("Extracting %s", fname)
		fullpath := filepath.Join(a.SecretsDir, fname)
		changed, err := updateSecret(fullpath, []byte(cfgFile.Value))
		if err != nil {
			return err
		}
		if changed && len(cfgFile.OnChanged) > 0 {
			log.Printf("Running on-change command for %s: %v", fname, cfgFile.OnChanged)
			cmd := exec.Command(cfgFile.OnChanged[0], cfgFile.OnChanged[1:]...)
			cmd.Env = append(os.Environ(), "CONFIG_FILE="+fullpath)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				log.Printf("Unable to run command: %v", err)
			}
		}
	}
	return nil
}

func close(c io.Closer, name string) {
	err := c.Close()
	if err != nil {
		log.Printf("Unexpected error closing %s: %s", name, err)
	}
}

// Do an atomic change to the secrets file so that a reader of the current
// secrets file won't hit race conditions.
func safeWrite(input io.ReadCloser, path string, modtime time.Time) error {
	defer close(input, path)

	safepath := path + ".tmp"
	to, err := os.OpenFile(safepath, os.O_RDWR|os.O_CREATE, 0644)
	defer close(to, safepath)
	if err != nil {
		return fmt.Errorf("Unable to create new secrets: %s - %w", path, err)
	}

	_, err = io.Copy(to, input)
	if err != nil {
		return fmt.Errorf("Unable to copy secrets to: %s - %w", path, err)
	}

	if err := os.Rename(safepath, path); err != nil {
		return fmt.Errorf("Unable to link secrets to: %s - %w", path, err)
	}

	err = os.Chtimes(path, modtime, modtime)
	if err != nil {
		return fmt.Errorf("Unable to set modified time %s - %w", path, err)
	}
	return nil
}

func (a *App) CheckIn() error {
	req, err := http.NewRequest("GET", a.configUrl, nil)
	if err != nil {
		return err
	}

	fi, err := os.Stat(a.EncryptedConfig)
	if err == nil {
		// Don't pull it down unless we need to
		ts := fi.ModTime().UTC().Format(time.RFC1123)
		req.Header.Add("If-Modified-Since", ts)
	}

	res, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("Unable to get: %s - %v", a.configUrl, err)
	}
	if res.StatusCode == 200 {
		modtime, err := time.Parse(time.RFC1123, res.Header.Get("Date"))
		if err != nil {
			log.Printf("Unable to get modtime of config file, defaulting to 'now': %s", err)
			modtime = time.Now()
		}
		if err := safeWrite(res.Body, a.EncryptedConfig, modtime); err != nil {
			return err
		}
	} else if res.StatusCode == 304 {
		log.Println("Config on server has not changed")
		return NotModifiedError
	} else if res.StatusCode == 204 {
		log.Println("Device has no config defined on server")
		return NotModifiedError
	} else {
		msg, _ := ioutil.ReadAll(res.Body)
		res.Body.Close()
		return fmt.Errorf("Unable to get %s - HTTP_%d: %s", a.configUrl, res.StatusCode, string(msg))
	}
	return a.Extract()
}

func (a *App) CallInitFunctions() error {
	for name, cb := range initFunctions {
		log.Printf("Running %s initialization", name)
		if err := cb(a); err != nil {
			return err
		}
	}
	return nil
}
