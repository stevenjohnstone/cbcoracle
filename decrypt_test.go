package cbcoracle

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
  "context"
	"testing"
)

func check(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecryptBlock(t *testing.T) {
	key := make([]byte, aes.BlockSize)
	block, err := aes.NewCipher(key)
	check(t, err)
	plaintext := []byte("This is a test which is longer than one block")
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize

	plaintext = append(plaintext, pad(padding)...)
	ciphertext := make([]byte, len(plaintext))
	iv := make([]byte, aes.BlockSize)

	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext, plaintext)

	oracle := func(ctx context.Context, iv, cipherblock []byte) bool {
    if ctx.Err() != nil {
      t.Logf("context cancelled")
    }
		decrypter := cipher.NewCBCDecrypter(block, iv)
		plaintextblock := make([]byte, aes.BlockSize)
		decrypter.CryptBlocks(plaintextblock, cipherblock)
		for p := aes.BlockSize; p > 0; p-- {
			if bytes.Equal(pad(p), plaintextblock[aes.BlockSize-p:]) {
				return true
			}
		}
		return false
	}

	result, err := Decrypt(iv, ciphertext, oracle)
	check(t, err)

	if !bytes.Equal(result, plaintext) {
		t.Errorf("result != plaintext,\n%+v !=\n%+v\n", result, plaintext)
	}
}
