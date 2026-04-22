package rubato

import (
	"fmt"

	"github.com/hosseinabdinf/sherdal/hhe/rubato"

	"github.com/hosseinabdinf/sherdal/ske"
	rubato2 "github.com/hosseinabdinf/sherdal/ske/rubato"
)

func run() {
	symParams := rubato2.Parameter{
		LogN:      16,
		BlockSize: 16,
		Modulus:   rubato2.Rubato5Param2616.Modulus,
		Rounds:    2,
		Sigma:     0,
	}

	cfg := rubato.Config{
		Preset:          rubato.Rubato128S,
		BGVLogN:         14,
		SymmetricParams: symParams,
	}

	rubato, err := rubato.NewRubato(cfg)
	if err != nil {
		panic(err)
	}

	key := []uint64{1, 3, 5, 7, 9, 11, 13, 15, 2, 4, 6, 8, 10, 12, 14, 16}
	if err := rubato.EncryptSymmetricKey(key); err != nil {
		panic(err)
	}

	plaintext := ske.Plaintext{1, 2, 3, 4, 5, 6, 7, 8}
	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	symCipher := rubato2.NewRubato(key, cfg.SymmetricParams).NewEncryptor().EncryptWithNonce(plaintext, nonce)

	heCipher, err := rubato.TranscipherSymCiphertext(symCipher, nonce)
	if err != nil {
		panic(err)
	}

	decrypted, err := rubato.Decrypt(heCipher, len(plaintext))
	if err != nil {
		panic(err)
	}

	fmt.Printf("Rubato ske ciphertext: %v\n", []uint64(symCipher))
	fmt.Printf("Rubato decrypted HE plaintext: %v\n", decrypted)
}
