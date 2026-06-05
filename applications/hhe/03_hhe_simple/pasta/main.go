package pasta

import (
	"fmt"

	"github.com/hosseinabdinf/sherdal/hhe/pasta"

	"github.com/hosseinabdinf/sherdal/ske"
	pasta2 "github.com/hosseinabdinf/sherdal/ske/pasta"
)

func run() {
	symParams := pasta2.Pasta4Param3215

	cfg := pasta.Config{
		Preset:          pasta.Pasta4_3215,
		BGVLogN:         15,
		SymmetricParams: symParams,
	}

	hePasta, err := pasta.NewPasta(cfg)
	if err != nil {
		panic(err)
	}

	key := make([]uint64, symParams.KeySize)
	for i := range key {
		key[i] = uint64(i + 1)
	}
	if err := hePasta.EncryptSymmetricKey(key); err != nil {
		panic(err)
	}

	plaintext := ske.Plaintext{1, 2, 3, 4, 5, 6, 7, 8}
	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7}

	symCipher := encryptWithHheCounters(key, plaintext, nonce, cfg.SymmetricParams)

	heCipher, err := hePasta.TranscipherSymCiphertext(symCipher, nonce)
	if err != nil {
		panic(err)
	}

	decrypted, err := hePasta.Decrypt(heCipher, len(plaintext))
	if err != nil {
		panic(err)
	}

	fmt.Printf("Pasta ske ciphertext: %v\n", []uint64(symCipher))
	fmt.Printf("Pasta decrypted HE plaintext: %v\n", decrypted)
}
