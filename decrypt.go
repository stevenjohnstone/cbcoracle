package cbcoracle

import (
	"context"
	"fmt"
	"sync"
)

func xor1(a []byte, b byte) []byte {
	r := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		r[i] = a[i] ^ b
	}
	return r
}

func xor(a, b []byte) []byte {
	r := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		r[i] = a[i] ^ b[i]
	}
	return r
}

func DecryptBlock(blockSize int, iv, cipherblock []byte, oracle func(ctx context.Context, iv, cipherblock []byte) bool) ([]byte, error) {
	result := make([]byte, blockSize)
	if remainder := len(cipherblock) % blockSize; remainder != 0 {
		return result, fmt.Errorf("len(cipherblock)%%blockSize == %d", remainder)
	}

	for idx := blockSize - 1; idx > -1; idx-- {
		padval := byte(blockSize - idx)
		ctx := context.Background()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		wg := sync.WaitGroup{}
		for candidate := 255; candidate > -1; candidate-- {
			wg.Add(1)
			go func(candidate, idx int) {
				defer wg.Done()
				candidateIV := xor1(result, padval)
				candidateIV[idx] = byte(candidate)
				if oracle(ctx, candidateIV, cipherblock) {
					if padval == 1 {
						// check for false positive
						candidateIV[idx-1] ^= 1
						if !oracle(ctx, candidateIV, cipherblock) {
							// false positive
							return
						}
					}
					cancel()
					result[idx] = byte(candidate) ^ padval
					return
				}
			}(candidate, idx)
		}
		wg.Wait()
	}
	return xor(result, iv), nil
}

func Decrypt(iv, ciphertext []byte, oracle func(ctx context.Context, iv, cipherblock []byte) bool) ([]byte, error) {
	res := make([]byte, len(ciphertext))
	blockSize := len(iv)

	for i := 0; i < (len(ciphertext) / blockSize); i++ {
		ct := append(ciphertext[i*blockSize:(i+1)*blockSize], []byte{}...)
		localIV := iv
		if i > 0 {
			localIV = append(ciphertext[(i-1)*blockSize:i*blockSize], []byte{}...)
		}
		plaintextBlock, err := DecryptBlock(blockSize, localIV, ct, oracle)
		if err != nil {
			return res, err
		}
		copy(res[i*blockSize:], plaintextBlock)
	}

	return res, nil
}
