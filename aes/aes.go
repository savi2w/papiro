package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

const SaltLen = 16
const Iter = 102400
const KeyLen = 32
const NonceLen = 12

func Encrypt(data []byte, password []byte) (result []byte, err error) {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	key := pbkdf2.Key(password, salt, Iter, KeyLen, sha3.New256)

	nonce := make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	cipher := gcm.Seal(nil, nonce, data, nil)

	return append(salt, append(nonce, cipher...)...), nil
}

func Decrypt(data []byte, password []byte) (result []byte, err error) {
	if len(data) < SaltLen+NonceLen {
		return nil, errors.New("data []byte is too short")
	}

	salt := data[:SaltLen]
	nonce := data[SaltLen : SaltLen+NonceLen]
	seal := data[SaltLen+NonceLen:]

	key := pbkdf2.Key(password, salt, Iter, KeyLen, sha3.New256)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plain, err := gcm.Open(nil, nonce, seal, nil)
	if err != nil {
		return nil, err
	}

	return plain, nil
}
