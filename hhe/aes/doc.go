// Package aes implements AES-128 in CTR mode for the HHE pipeline.
//
// It provides AESCtr for both reference CTR decryption (using the Go standard
// library) and homomorphic transciphering over CKKS/Lattigo ciphertexts. The
// implementation targets 16-byte keys and a 16-byte IV.
package aes
