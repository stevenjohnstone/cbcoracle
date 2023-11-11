package cbcoracle

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func TestEncrypt(t *testing.T) {
	key := make([]byte, aes.BlockSize)
	block, err := aes.NewCipher(key)
	check(t, err)

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

	plaintexts := [][]byte{
		[]byte("let's encrypt this using a padding oracle!"),
		[]byte("0123456789ABCDEF"), // aligned
	}
	for _, plaintext := range plaintexts {
		plaintextPadded := append(plaintext, pad(aes.BlockSize-len(plaintext)%aes.BlockSize)...)

		iv, ciphertext, err := Encrypt(aes.BlockSize, plaintext, oracle)
		check(t, err)

		plaintext2 := make([]byte, len(plaintextPadded))

		decrypter := cipher.NewCBCDecrypter(block, iv)
		decrypter.CryptBlocks(plaintext2, ciphertext)
		t.Logf("plaintext2 = %q\n", plaintext2)

		if !bytes.Equal(plaintextPadded, plaintext2) {
			t.Errorf("plaintextPadded != plaintext2, %+v != %+v\n", plaintextPadded, plaintext2)
		}
	}
}
