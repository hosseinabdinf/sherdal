package main

import (
	"log"

	"github.com/hosseinabdinf/sherdal/hhe/aes"
	symAes "github.com/hosseinabdinf/sherdal/ske/aes"

	// "fmt"
	bootstrapping2 "github.com/hosseinabdinf/sherdal/internal/aes_bootstrapping"

	// "github.com/hosseinabdinf/sherdal/utils" // Removed unused import

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func main() {
	// ------------------------------------
	// 				Client Side
	// ------------------------------------

	// 1. Generate a symmetric AES key
	symmetricKey := symAes.GenerateSymKey(symAes.GetDefaultParams())

	// 2. Encrypt plaintext using AES_CTR
	plaintext := []byte("This is a secret message that will be encrypted using AES and then decrypted using Homomorphic Encryption!")
	log.Printf("Original plaintext: %s\n", string(plaintext))

	// Create the AES CTR instance for symmetric encryption
	symAESCtr, err := symAes.NewAESCtr(symmetricKey, symAes.GetDefaultParams())
	if err != nil {
		log.Fatalf("Error creating symmetric AES CTR: %v", err)
	}
	symEncryptor := symAESCtr.NewEncryptor()

	encryptedSymBlocks, err := symEncryptor.Encrypt(plaintext)
	if err != nil {
		log.Fatalf("Error encrypting with AES_CTR: %v", err)
	}
	log.Printf("Symmetrically encrypted blocks (first 10 bytes): %x...\n", encryptedSymBlocks[:10])

	// 3. Encrypt the symmetric key using Homomorphic Encryption
	// Using default parameters for HE
	btpLit := bootstrapping2.DefaultParametersSparse[0]
	params, err := ckks.NewParametersFromLiteral(btpLit.SchemeParams)
	if err != nil {
		log.Fatalf("Error creating CKKS parameters: %v", err)
	}
	btpParams, err := bootstrapping2.NewParametersFromLiteral(params, btpLit.BootstrappingParams)
	if err != nil {
		log.Fatalf("Error creating aes_bootstrapping parameters: %v", err)
	}

	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()

	evk, _, err := btpParams.GenEvaluationKeys(sk)
	if err != nil {
		log.Fatalf("Error generating evaluation keys: %v", err)
	}

	encoder := ckks.NewEncoder(params)
	heEncryptor := rlwe.NewEncryptor(params, pk)

	// Encode the symmetric key into a plaintext for HE encryption
	symmetricKeyFloats := make([]float64, params.MaxSlots())
	for i, val := range symmetricKey {
		if i >= params.MaxSlots() {
			break
		}
		symmetricKeyFloats[i] = float64(val)
	}

	hePlainKey := ckks.NewPlaintext(params, params.MaxLevel())
	encoder.Encode(symmetricKeyFloats, hePlainKey)

	encryptedHEKey, err := heEncryptor.EncryptNew(hePlainKey)
	if err != nil {
		log.Fatalf("Error encrypting symmetric key homomorphically: %v", err)
	}
	log.Printf("Homomorphically encrypted symmetric key (first 10 coefficients of poly[0]): %v...\n", encryptedHEKey.Value[0].Coeffs[0][:10])

	// ------------------------------------
	// 				Server Side
	// ------------------------------------

	// 1. Receive encrypted blocks and encrypted key (simulated by passing directly)

	// 2. Perform transciphering to convert symmetrically encrypted blocks to HE ciphertexts
	decryptor := rlwe.NewDecryptor(params, sk)

	// Convert ske.Key to []uint8 for aes.NewAESCtr
	symmetricKeyUint8 := make([]uint8, len(symmetricKey))
	for i, val := range symmetricKey {
		symmetricKeyUint8[i] = uint8(val)
	}

	// Create a dummy IV for aes.NewAESCtr as well
	heIV := make([]byte, 16)
	// _, err = rand.Read(heIV)
	// if err != nil {
	// 	log.Fatalf("Error generating IV for HE AES: %v", err)
	// }

	// The transcipherer is an AESCtr instance
	heAESCtr, err := aes.NewAESCtr(symmetricKeyUint8, params, btpParams, evk, encoder, heEncryptor, decryptor, heIV)
	if err != nil {
		log.Fatalf("Error creating HE AES CTR: %v", err)
	}

	// Transcipher by calling HEDecrypt method on the heAESCtr instance
	// The `ciphertexts` argument should be the raw symmetric ciphertext bytes
	// The `bits` argument represents the length of the original plaintext in bits (or just length in bytes * 8 if each byte is 8 bits)
	// For simplicity, using len(plaintext) * 8
	heCiphertextBlocks := heAESCtr.HEDecrypt(encryptedSymBlocks, len(plaintext)*8)
	log.Printf("Transciphered HE ciphertext (first block, first 10 coefficients of poly[0]): %v...\n", heCiphertextBlocks[0].Value[0].Coeffs[0][:10])

	// 3. Perform HE Decryption
	// The HEDecrypt returns a slice of ciphertexts. Let's decrypt the first one.
	// We need an empty plaintext to store the decrypted result.
	heDecryptedPlaintext := ckks.NewPlaintext(params, heCiphertextBlocks[0].Level())
	decryptor.Decrypt(heCiphertextBlocks[0], heDecryptedPlaintext)

	// Decode the plaintext to get the float values.
	decodedFloats := make([]float64, params.MaxSlots())
	encoder.Decode(heDecryptedPlaintext, decodedFloats)

	log.Printf("Raw decrypted HE data (first 10 values): %v...\n", decodedFloats[:10])

	// 4. Verify decryption
	// This verification is still simplified. A proper verification would involve comparing
	// the `decodedFloats` with the `plaintext` after it has been encoded in the same way.
	// For now, let's just indicate successful execution if we reach here without fatal errors.
	log.Println("Decryption process completed. \n" +
		"Verification of homomorphic decryption would require a more detailed comparison of decoded values with the original plaintext representation.\n")

}
