package Encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"strings"
)

func Encode(value, key string) string {
	if ok, err := ParseValue(value, key, false); err != nil {
		return err.Error()
	} else {
		return strings.Trim(ok, "\n")
	}
}

func Decode(value, key string) string {
	if ok, err := ParseValue(value, key, true); err != nil {
		return err.Error()
	} else {
		return strings.Trim(ok, "\n")
	}
}

func ParseValue(PassThrough, Key string, Decrypt bool) (string, error) {
	if !Decrypt {
		block, err := aes.NewCipher([]byte(Key))
		if err != nil {
			return "", err
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%x\n", aesgcm.Seal(nil, make([]byte, 12), []byte(PassThrough), nil)), nil
	} else {
		block, err := aes.NewCipher([]byte(Key))
		if err != nil {
			return "", err
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}
		Nonce, err := hex.DecodeString(PassThrough)
		if err != nil {
			return "", err
		}
		plaintext, err := aesgcm.Open(nil, make([]byte, 12), Nonce, nil)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s", string(plaintext)), nil
	}
}
