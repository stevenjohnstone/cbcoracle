package cbcoracle

import (
  "bytes"
  "context"
)

func pad(n int) []byte {
	return bytes.Repeat([]byte{byte(n)}, n)
}

func Encrypt(blockSize int, plaintext []byte, oracle func(ctx context.Context, iv, ciphertextblock []byte) bool) ([]byte, []byte, error) {
	ciphertext := []byte{}
	zeroIV := make([]byte, blockSize)
	decryptBlock := func(plaintextBlock []byte) ([]byte, error) {
		return DecryptBlock(blockSize, zeroIV, plaintextBlock, oracle)
	}

	lastBlock := func(input []byte) []byte {
		return input[len(input)-blockSize:]
	}

	plaintext = append(plaintext, pad(blockSize-len(plaintext)%blockSize)...)

	nextBlock := zeroIV // junk block to get us started
	for len(plaintext) > 0 {
		ciphertext = append(nextBlock, ciphertext...)
		p, err := decryptBlock(nextBlock)
		if err != nil {
			return nextBlock, ciphertext, err
		}

		// now we need to choose a previous cipher block, c, such that
		// c ^ p = lastBlock(plaintext) Then the last block
		// will decrypt correctly.

		nextBlock = xor(p, lastBlock(plaintext))
		plaintext = plaintext[:len(plaintext)-blockSize]
	}
	return nextBlock, ciphertext, nil
}
