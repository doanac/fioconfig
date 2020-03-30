package internal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/crypto/ecies"
	"testing"
)

const pub_pem = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2Lk7kpRnR3lJez9536ADaNtrDYIc
pUk69sabVt61KujrrN/57RQWfRHzc2wbU/mit/ndbbQVuYSZPlOwYKP96A==
-----END PUBLIC KEY-----`

const pkey_pem = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg3crfB0FprBSTYR+g
NMpyLSTSUBfiixurSy3gsgXSeDChRANCAATYuTuSlGdHeUl7P3nfoANo22sNghyl
STr2xptW3rUq6Ous3/ntFBZ9EfNzbBtT+aK3+d1ttBW5hJk+U7Bgo/3o
-----END PRIVATE KEY-----`

const rsa_pub = `
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCb+NjecmqMWhe+qIWD08PzR2l3
QAZ1lgpjaldbTNria/I6eW/v+dhAtLBt1M7ZCZo0bp93gFkuR98KW1YipP0nv5l+
WJsYjLYU0O03HBOQ3UyJw78e8maEetcW4UFRKFa5SFGtlf63V4bEMTAtDLavivz5
IiTWAouywktH5ZGRRQIDAQAB
-----END PUBLIC KEY-----`

const rsa_priv = `
-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJv42N5yaoxaF76o
hYPTw/NHaXdABnWWCmNqV1tM2uJr8jp5b+/52EC0sG3UztkJmjRun3eAWS5H3wpb
ViKk/Se/mX5YmxiMthTQ7TccE5DdTInDvx7yZoR61xbhQVEoVrlIUa2V/rdXhsQx
MC0Mtq+K/PkiJNYCi7LCS0flkZFFAgMBAAECgYAwpmwu5o1pfeiOJc6Pkgw64/l3
otbg8o4G+HKLHevgWD9UEfDib5IOjM3DVG+4rxAUbrT692PZ1b0yY874O3Ji6OeC
v3PO6qyT82O9tOlpEi0CR7uOgs86ePYp03WRoeIheacLiGq6UboOUINpYD8PCQ+C
es5pWOHlV3WG7MHcOQJBAMwFc0Fbsrue/z3druF8GYk1xs7w3ax27SU9/IvFqfAZ
L0GVMz7QQG0urJz1Yy/tPlAcCuh5FjBAwbE8MgnRIx8CQQDDtY9S+f1ESQTk1109
rvW+Qol9iVLzj7J7fEO3JZRxEuSfQ0Neythw0F1gXKCwuYWQ9N+RsrXWNZ/S7sux
NoMbAkEAlb0aTkni8FlNtDZT+CKBC3dwpsmZqM7QVpkcFenJQ/L4AAZlSiDGaFvt
THW9iptxNJKgXucgJeIhRteLUjEwuQJBAIJ4BUZB1e+x5gtQ753xh24BGXuRErXA
dDISU2pDKUSAXd02kDEfdU8v+TAGUDHAXCSYunp88vAM67FI9I39U0UCQEElOxUg
2/ZbfxFSAbjQXbQeMTacKLYp46/k/L6JD+Oy3NsYHXjHWbPJHkL+5lzGO61f64ir
yxxo3aqLgjxem6A=
-----END PRIVATE KEY-----`

func eciesEncrypt(t *testing.T, config map[string]*ConfigFile) {
	block, _ := pem.Decode([]byte(pub_pem))
	if block == nil {
		t.Fatalf("failed to parse certificate PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse DER encoded public key: %s", err)
	}

	ecpub := pub.(*ecdsa.PublicKey)
	eciesPub := ecies.ImportECDSAPublic(ecpub)

	for fname, cfgFile := range config {
		enc, err := ecies.Encrypt(rand.Reader, eciesPub, []byte(cfgFile.Value), nil, nil)
		if err != nil {
			t.Fatalf("Unable to encrypt %s: %s", fname, err)
		}
		cfgFile.Value = base64.StdEncoding.EncodeToString(enc)
	}
}

func rsaEncrypt(t *testing.T, config map[string]*ConfigFile) {
	block, _ := pem.Decode([]byte(rsa_pub))
	if block == nil {
		t.Fatalf("failed to parse certificate PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse DER encoded public key: %s", err)
	}

	rsapub := pub.(*rsa.PublicKey)
	for fname, cfgFile := range config {
		// RSA can't do big buffers, so generate a 32 byte random key.
		// Encrypt that with RSA. Use that key to do symetric
		// encryption on the buffer and store that
		b := make([]byte, 32)
		_, err := rand.Read(b)
		if err != nil {
			t.Fatalf("unable to generate random key: %s", err)
		}

		enc, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsapub, b, nil)
		if err != nil {
			t.Fatalf("Unable to encrypt %s: %s", fname, err)
		}

		filebytes := []byte(cfgFile.Value)
		ciphertext := make([]byte, len(enc)+aes.BlockSize+len(filebytes))
		copy(ciphertext, enc)

		// from https://golang.org/pkg/crypto/cipher/#example_NewCFBDecrypter
		block, err := aes.NewCipher(b)
		if err != nil {
			t.Fatalf("Unable to create aes cipher: %s", err)
		}
		iv := ciphertext[len(enc) : len(enc)+aes.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			t.Fatalf("Unable to iv: %s", err)
		}

		stream := cipher.NewCFBEncrypter(block, iv)
		stream.XORKeyStream(ciphertext[len(enc)+aes.BlockSize:], filebytes)

		cfgFile.Value = base64.StdEncoding.EncodeToString(ciphertext)
	}
}

type keyWrapper struct {
	pkey    string
	encrypt func(t *testing.T, config map[string]*ConfigFile)
}

func testWrapper(t *testing.T, key keyWrapper, testFunc func(app *App, tempdir string)) {
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(dir)

	if err := ioutil.WriteFile(filepath.Join(dir, "pkey.pem"), []byte(key.pkey), 0644); err != nil {
		t.Fatal(err)
	}

	config := make(map[string]*ConfigFile)
	config["foo"] = &ConfigFile{Value: "foo file value"}
	config["bar"] = &ConfigFile{
		Value:     "bar file value",
		OnChanged: []string{"/usr/bin/touch", filepath.Join(dir, "bar-changed")},
	}
	random := make([]byte, 1024) // 1MB random file
	_, err = rand.Read(random)
	if err != nil {
		t.Fatalf("Unable to create random buffer: %v", err)
	}
	config["random"] = &ConfigFile{Value: base64.StdEncoding.EncodeToString(random)}

	key.encrypt(t, config)
	if config["foo"].Value == "foo file value" {
		t.Fatal("Encryption did not occur")
	}
	app, err := NewApp(dir, dir, true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(app.EncryptedConfig, b, 0644); err != nil {
		t.Fatal(err)
	}
	testFunc(app, dir)
}

func TestUnmarshall(t *testing.T) {
	ec := keyWrapper{pkey_pem, eciesEncrypt}
	testWrapper(t, ec, func(app *App, tempdir string) {
		unmarshalled, err := Unmarshall(app.Crypto, app.EncryptedConfig)
		if err != nil {
			t.Fatal(err)
		}
		if string(unmarshalled["foo"].Value) != "foo file value" {
			t.Fatalf("Unable to unmarshal 'foo'")
		}
		if string(unmarshalled["bar"].Value) != "bar file value" {
			t.Fatalf("Unable to unmarshal 'foo'")
		}
		if len(unmarshalled["random"].Value) != 1368 {
			t.Fatal("Invalid random unmarshalling")
		}
	})
	r := keyWrapper{rsa_priv, rsaEncrypt}
	testWrapper(t, r, func(app *App, tempdir string) {
		unmarshalled, err := Unmarshall(app.Crypto, app.EncryptedConfig)
		if err != nil {
			t.Fatal(err)
		}
		if string(unmarshalled["foo"].Value) != "foo file value" {
			t.Fatalf("Unable to unmarshal 'foo'")
		}
		if string(unmarshalled["bar"].Value) != "bar file value" {
			t.Fatalf("Unable to unmarshal 'foo'")
		}
		if len(unmarshalled["random"].Value) != 1368 {
			t.Fatal("Invalid random unmarshalling")
		}
	})
}

func assertFile(t *testing.T, path string, contents []byte) {
	buff, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if contents != nil && !bytes.Equal(buff, contents) {
		t.Fatalf("Unexpected contents: %s != %s", contents, buff)
	}
}

func TestExtract(t *testing.T) {
	ec := keyWrapper{pkey_pem, eciesEncrypt}
	testWrapper(t, ec, func(app *App, tempdir string) {
		if err := app.Extract(); err != nil {
			t.Fatal(err)
		}

		assertFile(t, filepath.Join(tempdir, "foo"), []byte("foo file value"))
		assertFile(t, filepath.Join(tempdir, "bar"), []byte("bar file value"))
		assertFile(t, filepath.Join(tempdir, "random"), nil)
		barChanged := filepath.Join(tempdir, "bar-changed")
		assertFile(t, barChanged, nil)

		// Make sure files that don't change aren't updated
		os.Remove(barChanged)
		if err := app.Extract(); err != nil {
			t.Fatal(err)
		}
		_, err := os.Stat(barChanged)
		if !os.IsNotExist(err) {
			t.Fatal("OnChanged called when file has not changed")
		}
	})
}

func TestCheckBad(t *testing.T) {
	ec := keyWrapper{pkey_pem, eciesEncrypt}
	testWrapper(t, ec, func(app *App, tempdir string) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer ts.Close()

		app.client = ts.Client()
		app.configUrl = ts.URL

		err := app.CheckIn()
		if err == nil {
			t.Fatal("Checkin should have gotten a 404")
		}

		if !strings.HasSuffix(strings.TrimSpace(err.Error()), "HTTP_404: 404 page not found") {
			t.Fatalf("Unexpected response: '%s'", err)
		}
	})
}

func TestCheckGood(t *testing.T) {
	ec := keyWrapper{pkey_pem, eciesEncrypt}
	testWrapper(t, ec, func(app *App, tempdir string) {
		encbuf, err := ioutil.ReadFile(app.EncryptedConfig)
		if err != nil {
			t.Fatal(err)
		}
		// Remove this file so we can be sure the check-in creates it
		os.Remove(app.EncryptedConfig)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(r.Header.Get("If-Modified-Since")) > 0 {
				w.WriteHeader(304)
				return
			}
			if _, err := w.Write(encbuf); err != nil {
				t.Fatal(err)
			}
		}))
		defer ts.Close()

		app.client = ts.Client()
		app.configUrl = ts.URL

		if err := app.CheckIn(); err != nil {
			t.Fatal(err)
		}

		// Make sure encrypted file exists
		assertFile(t, app.EncryptedConfig, nil)

		// Make sure decrypted files exist
		assertFile(t, filepath.Join(tempdir, "foo"), []byte("foo file value"))
		assertFile(t, filepath.Join(tempdir, "bar"), []byte("bar file value"))
		assertFile(t, filepath.Join(tempdir, "random"), nil)

		// Now make sure the if-not-modified logic works
		if err := app.CheckIn(); err != NotModifiedError {
			t.Fatal(err)
		}
	})
}

func TestInitFunctions(t *testing.T) {
	called := false
	initFunctions["OkComputer"] = func(app *App) error {
		called = true
		return nil
	}
	ec := keyWrapper{pkey_pem, eciesEncrypt}
	testWrapper(t, ec, func(app *App, tempdir string) {
		if err := app.CallInitFunctions(); err != nil {
			t.Fatal(err)
		}
	})
	if !called {
		t.Fatal("init function not called")
	}
}
