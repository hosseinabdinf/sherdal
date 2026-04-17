package internal

import (
	"encoding/binary"
	"fmt"
	"sherdal/ske"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func ExpandNonceBlocks(seed []byte, numBlocks int) [][]byte {
	base := ske.NonceSeed(seed)
	nonces := make([][]byte, numBlocks)
	for i := 0; i < numBlocks; i++ {
		nonce := make([]byte, ske.NonceSize)
		ske.FillNonce(nonce, base, i)
		nonces[i] = nonce
	}
	return nonces
}

func ExpandRubatoCounters(numBlocks int) [][]byte {
	counters := make([][]byte, numBlocks)
	for i := 0; i < numBlocks; i++ {
		counter := make([]byte, 8)
		binary.BigEndian.PutUint64(counter, uint64(i+1))
		counters[i] = counter
	}
	return counters
}

func PackCiphertextBlocks(ciphertext []uint64, blockWidth int, slots int) [][]uint64 {
	numBlocks := ske.CeilDiv(len(ciphertext), blockWidth)
	packed := make([][]uint64, blockWidth)
	for component := 0; component < blockWidth; component++ {
		packed[component] = make([]uint64, slots)
		for block := 0; block < numBlocks; block++ {
			idx := block*blockWidth + component
			if idx < len(ciphertext) {
				packed[component][block] = ciphertext[idx]
			}
		}
	}
	return packed
}

func FlattenDecryptedBlocks(outputs [][]uint64, blockWidth, plainSize int) []uint64 {
	plaintext := make([]uint64, plainSize)
	if len(outputs) == 0 {
		return plaintext
	}
	numBlocks := len(outputs)
	for block := 0; block < numBlocks; block++ {
		for component := 0; component < blockWidth; component++ {
			idx := block*blockWidth + component
			if idx >= plainSize || component >= len(outputs[block]) {
				continue
			}
			plaintext[idx] = outputs[block][component]
		}
	}
	return plaintext
}

func TranscipherPacked(runtime *BGVRuntime, evaluator *FVHeraEvaluator, nonces [][]byte, packed [][]uint64, key []*rlwe.Ciphertext) ([]*rlwe.Ciphertext, error) {
	keystream, err := evaluator.Crypt(nonces, key)
	if err != nil {
		return nil, err
	}
	return SubtractPackedPlain(runtime, keystream, packed)
}

func SubtractPackedPlain(runtime *BGVRuntime, keystream []*rlwe.Ciphertext, packed [][]uint64) ([]*rlwe.Ciphertext, error) {
	if len(keystream) != len(packed) {
		return nil, fmt.Errorf("packed/plain component mismatch: got %d packed components for %d ciphertexts", len(packed), len(keystream))
	}

	transciphered := make([]*rlwe.Ciphertext, len(keystream))
	for i := range keystream {
		ct := keystream[i].CopyNew()
		if err := runtime.evaluator.Mul(ct, -1, ct); err != nil {
			return nil, fmt.Errorf("negate keystream component %d: %w", i, err)
		}
		if err := runtime.evaluator.Add(ct, packed[i], ct); err != nil {
			return nil, fmt.Errorf("add packed symmetric ciphertext component %d: %w", i, err)
		}
		transciphered[i] = ct
	}
	return transciphered, nil
}
