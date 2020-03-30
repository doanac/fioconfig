package internal

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

type RsaCrypto struct {
	PrivKey *rsa.PrivateKey
}

func NewRsaHandler(privKey crypto.PrivateKey) CryptoHandler {
	if rsa, ok := privKey.(*rsa.PrivateKey); ok {
		return &RsaCrypto{rsa}
	}
	return nil
}

func (r *RsaCrypto) Decrypt(value string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("Unable to base64 decode: %v", err)
	}
	encKey := data[:r.PrivKey.Size()]
	decryptedKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, r.PrivKey, encKey, nil)
	if err != nil {
		return nil, fmt.Errorf("Unable to RSA OAEP decrypt %v", err)
	}

	//https://golang.org/pkg/crypto/cipher/#example_NewCFBDecrypter
	block, err := aes.NewCipher(decryptedKey)
	if err != nil {
		panic(err)
	}
	ciphertext := data[r.PrivKey.Size():]
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}
