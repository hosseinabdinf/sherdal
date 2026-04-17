package he1hera

import (
	"fmt"
	"sherdal/hhe/hera"
	"sherdal/ske"
	hera2 "sherdal/ske/hera"
)

func run() {
	cfg := hera.Config{
		Preset:          hera.Hera128AF,
		BGVLogN:         15,
		SymmetricParams: hera2.Hera4Params2516,
	}

	hera, err := hera.NewHera(cfg)
	if err != nil {
		panic(err)
	}

	key := []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	if err := hera.EncryptSymmetricKey(key); err != nil {
		panic(err)
	}

	plaintext := ske.Plaintext{1, 2, 5, 5, 5, 6, 7, 8}
	nonce := []byte{10, 11, 12, 13, 14, 15, 16, 17}
	symCipher := hera2.NewHera(key, hera2.Hera4Params2516).NewEncryptor().EncryptWithNonce(plaintext, nonce)

	heCipher, err := hera.TranscipherSymCiphertext(symCipher, nonce)
	if err != nil {
		panic(err)
	}

	decrypted, err := hera.Decrypt(heCipher, len(plaintext))
	if err != nil {
		panic(err)
	}

	fmt.Printf("Hera ske ciphertext: %v\n", []uint64(symCipher))
	fmt.Printf("Hera decrypted HE plaintext: %v\n", decrypted)
}
