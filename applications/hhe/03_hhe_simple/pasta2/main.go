package pasta2

import (
	"fmt"

	"github.com/hosseinabdinf/sherdal/hhe/pasta2"

	"github.com/hosseinabdinf/sherdal/ske"
	sympasta2 "github.com/hosseinabdinf/sherdal/ske/pasta2"
)

func run() {
	symParams := sympasta2.Pasta4Param3215

	cfg := pasta2.Config{
		Preset:          pasta2.Pasta2_4_3215,
		BGVLogN:         15,
		SymmetricParams: symParams,
	}

	hePasta, err := pasta2.NewPasta2(cfg)
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
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	encryptor := sympasta2.NewPasta2(key, symParams).NewEncryptor()
	symCipher := encryptor.EncryptWithNonce(plaintext, nonce)

	heCipher, err := hePasta.TranscipherSymCiphertext(symCipher, nonce)
	if err != nil {
		panic(err)
	}

	decrypted, err := hePasta.Decrypt(heCipher, len(plaintext))
	if err != nil {
		panic(err)
	}

	fmt.Printf("Pasta2 ske ciphertext: %v\n", []uint64(symCipher))
	fmt.Printf("Pasta2 decrypted HE plaintext: %v\n", decrypted)
}
