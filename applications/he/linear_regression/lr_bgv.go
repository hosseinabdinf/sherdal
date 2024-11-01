// This is a sample application for doing linear regression using bgv scheme

package linear_regression

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"math"
	"sherdal/utils"
)

type Client struct {
	logger    utils.Logger
	params    bgv.Parameters
	sk        []byte
	pk        []byte
	encoder   *bgv.Encoder
	encryptor *rlwe.Encryptor
	decryptor *rlwe.Decryptor
}

type Server struct {
	logger    utils.Logger
	params    bgv.Parameters
	pk        []byte
	evk       *rlwe.MemEvaluationKeySet
	evaluator *bgv.Evaluator
}

func getParams(p []byte) (params bgv.Parameters) {
	err := params.UnmarshalBinary(p)
	utils.HandleError(err)
	return
}

// Setup generates key pairs and setup encoder, encryptor, and decryptor
// returns evaluation key
func (client *Client) Setup(pubParams []byte) (rPK []byte, rRLK []byte) {
	var err error

	client.params = getParams(pubParams)
	kgen := rlwe.NewKeyGenerator(client.params)
	sk, pk := kgen.GenKeyPairNew()

	client.sk, err = sk.MarshalBinary()
	utils.HandleError(err)

	client.pk, err = pk.MarshalBinary()
	utils.HandleError(err)

	client.encoder = bgv.NewEncoder(client.params)
	client.encryptor = bgv.NewEncryptor(client.params, pk)
	client.decryptor = bgv.NewDecryptor(client.params, sk)

	rlk := kgen.GenRelinearizationKeyNew(sk)

	rPK = client.pk
	rRLK, err = rlk.MarshalBinary()
	utils.HandleError(err)

	return
}

func (client *Client) Encrypt(input []uint64) (cipher []byte) {
	var err error

	maxSlot := client.params.MaxSlots()
	numBlock := int(math.Ceil(float64(len(input)) / float64(maxSlot)))
	client.logger.PrintFormatted("Number of Block: %d", numBlock)

	// encode the data
	var plaintext = bgv.NewPlaintext(client.params, client.params.MaxLevel())
	err = client.encoder.Encode(input, plaintext)

	var ciphertext *rlwe.Ciphertext
	ciphertext, err = client.encryptor.EncryptNew(plaintext)
	utils.HandleError(err)

	cipher, err = ciphertext.MarshalBinary()
	utils.HandleError(err)
	return
}

func (client *Client) Decrypt(cipher []byte) (res []uint64) {
	var err error
	var plaintext *rlwe.Plaintext
	var ciphertext *rlwe.Ciphertext

	err = ciphertext.UnmarshalBinary(cipher)
	utils.HandleError(err)

	plaintext = client.decryptor.DecryptNew(ciphertext)
	err = client.encoder.Decode(plaintext, res)
	utils.HandleError(err)
	return
}

// Setup initiate evaluator
func (server *Server) Setup(pubParams []byte, rlk []byte) {
	var err error

	params := getParams(pubParams)
	var rl = rlwe.NewRelinearizationKey(params)
	err = rl.UnmarshalBinary(rlk)
	utils.HandleError(err)

	server.evk = rlwe.NewMemEvaluationKeySet(rl)

	// scale invariant = false -> BGV Scheme
	server.evaluator = bgv.NewEvaluator(params, server.evk, false)
}

func (server *Server) Evaluate(ciphers []byte, weights []byte, biases []byte) (res []byte) {
	var err error
	c := rlwe.NewCiphertext(server.params, server.params.N(), server.params.MaxLevel())
	w := rlwe.NewCiphertext(server.params, server.params.N(), server.params.MaxLevel())
	b := rlwe.NewCiphertext(server.params, server.params.N(), server.params.MaxLevel())
	c.MarshalJSON()
	err = c.UnmarshalBinary(ciphers)
	utils.HandleError(err)

	err = w.UnmarshalBinary(weights)
	utils.HandleError(err)

	err = b.UnmarshalBinary(biases)
	utils.HandleError(err)

	// y = ax + b
	ax, err := server.evaluator.MulRelinNew(c, w)
	utils.HandleError(err)

	axb, err := server.evaluator.AddNew(ax, b)
	utils.HandleError(err)

	res, err = axb.MarshalBinary()
	utils.HandleError(err)

	return
}
