package rubato

import (
	"crypto/rand"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
	"golang.org/x/crypto/sha3"
	"sherdal/hhe/sym"
	mUtils "sherdal/utils"
)

type Rubato interface {
	NewEncryptor() Encryptor
	KeyStream(nonce []byte, counter []byte) sym.Block
}

type rubato struct {
	params    Parameter
	shake     sha3.ShakeHash
	secretKey sym.Key
	state     sym.Block
	rcs       sym.Matrix
	p         uint64
	sampler   *mUtils.GaussianSampler
}

// GenerateSymKey takes the parameter set and generate a secure symmetric key
func GenerateSymKey(params Parameter) (key sym.Key) {
	key = make(sym.Key, params.BlockSize)

	for i := 0; i < params.BlockSize; i++ {
		key[i] = mUtils.SampleZq(rand.Reader, params.Modulus)
	}

	return
}

// NewRubato return a new instance of Rubato cipher
func NewRubato(secretKey sym.Key, params Parameter) Rubato {
	if len(secretKey) != params.GetBlockSize() {
		panic("Invalid Key Length!")
	}

	state := make(sym.Block, params.GetBlockSize())
	rub := &rubato{
		params:    params,
		shake:     nil,
		secretKey: secretKey,
		state:     state,
		p:         params.GetModulus(),
		rcs:       nil,
		sampler:   nil,
	}
	return rub
}

func (rub *rubato) NewEncryptor() Encryptor {
	return &encryptor{rub: *rub}
}

// KeyStream returns a vector of [BlockSize - 4][uint64] elements as key stream
func (rub *rubato) KeyStream(nonce []byte, counter []byte) (ks sym.Block) {
	p := rub.params.GetModulus()
	rounds := rub.params.GetRounds()
	blockSize := rub.params.GetBlockSize()

	rub.initShake(nonce, counter)
	rub.initState()
	rub.initGaussianSampler()
	rub.generateRCs()

	// Initial AddRoundKey
	for i := 0; i < blockSize; i++ {
		rub.state[i] = (rub.state[i] + rub.rcs[0][i]) % p
	}

	// Round Functions
	for r := 1; r < rounds; r++ {
		rub.linearLayer()
		rub.sBoxFeistel()
		for i := 0; i < blockSize; i++ {
			rub.state[i] = (rub.state[i] + rub.rcs[r][i]) % p
		}
	}

	// Finalization
	rub.linearLayer()
	rub.sBoxFeistel()
	rub.linearLayer()

	// adding this noise will change the key randomly !!
	// cause lost very small part of plaintext
	if rub.params.GetSigma() > 0 {
		rub.addGaussianNoise()
	}

	for i := 0; i < blockSize; i++ {
		rub.state[i] = (rub.state[i] + rub.rcs[rounds][i]) % p
	}
	ks = rub.state[0 : blockSize-4]
	return
}

func (rub *rubato) initState() {
	for i := 0; i < rub.params.GetBlockSize(); i++ {
		rub.state[i] = uint64(i + 1)
	}
}

func (rub *rubato) initShake(nonce []byte, counter []byte) {
	shake := sha3.NewShake256()
	if _, err := shake.Write(nonce); err != nil {
		panic("Failed to init SHAKE128!")
	}
	if _, err := shake.Write(counter); err != nil {
		panic("Failed to init SHAKE128!")
	}
	rub.shake = shake
}

func (rub *rubato) initGaussianSampler() {
	prng, err := sampling.NewPRNG()
	mUtils.HandleError(err)

	sampler := mUtils.NewGaussianSampler(prng, mUtils.DiscreteGaussian{
		Sigma: rub.params.GetSigma(),
		Bound: 6 * rub.params.GetSigma(),
	})
	mUtils.HandleError(err)

	rub.sampler = sampler

	// init the random buffer
	randomBuff := make([]byte, 1024)
	_, err = prng.Read(randomBuff)
	mUtils.HandleError(err)
	rub.sampler.RandomBufferN = randomBuff
}

func (rub *rubato) generateRCs() {
	key := rub.secretKey
	blockSize := rub.params.GetBlockSize()
	p := rub.params.GetModulus()
	rounds := rub.params.GetRounds()
	// generate round constant and then calculate rc = rc * k % p for ARK function
	rcs := make(sym.Matrix, rounds+1)
	for r := 0; r <= rounds; r++ {
		rcs[r] = make([]uint64, blockSize)
		for i := 0; i < blockSize; i++ {
			rcs[r][i] = mUtils.SampleZq(rub.shake, p) * key[i] % p
		}
	}
	rub.rcs = rcs
}

func (rub *rubato) linearLayer() {
	blockSize := len(rub.state)
	p := rub.params.GetModulus()
	buf := make(sym.Block, blockSize)

	if blockSize == 16 {
		// MixColumns
		for row := 0; row < 4; row++ {
			for col := 0; col < 4; col++ {
				buf[row*4+col] = 2 * rub.state[row*4+col]
				buf[row*4+col] += 3 * rub.state[((row+1)%4)*4+col]
				buf[row*4+col] += rub.state[((row+2)%4)*4+col]
				buf[row*4+col] += rub.state[((row+3)%4)*4+col]
				buf[row*4+col] %= p
			}
		}
		// MixRows
		for row := 0; row < 4; row++ {
			for col := 0; col < 4; col++ {
				rub.state[row*4+col] = 2 * buf[row*4+col]
				rub.state[row*4+col] += 3 * buf[row*4+(col+1)%4]
				rub.state[row*4+col] += buf[row*4+(col+2)%4]
				rub.state[row*4+col] += buf[row*4+(col+3)%4]
				rub.state[row*4+col] %= p
			}
		}
	} else if blockSize == 36 {
		// MixColumns
		for row := 0; row < 6; row++ {
			for col := 0; col < 6; col++ {
				buf[row*6+col] = 4 * rub.state[row*6+col]
				buf[row*6+col] += 2 * rub.state[((row+1)%6)*6+col]
				buf[row*6+col] += 4 * rub.state[((row+2)%6)*6+col]
				buf[row*6+col] += 3 * rub.state[((row+3)%6)*6+col]
				buf[row*6+col] += rub.state[((row+4)%6)*6+col]
				buf[row*6+col] += rub.state[((row+5)%6)*6+col]
				buf[row*6+col] %= p
			}
		}
		// MixRows
		for row := 0; row < 6; row++ {
			for col := 0; col < 6; col++ {
				rub.state[row*6+col] = 4 * buf[row*6+col]
				rub.state[row*6+col] += 2 * buf[row*6+(col+1)%6]
				rub.state[row*6+col] += 4 * buf[row*6+(col+2)%6]
				rub.state[row*6+col] += 3 * buf[row*6+(col+3)%6]
				rub.state[row*6+col] += buf[row*6+(col+4)%6]
				rub.state[row*6+col] += buf[row*6+(col+5)%6]
				rub.state[row*6+col] %= p
			}
		}
	} else if blockSize == 64 {
		// MixColumns
		for row := 0; row < 8; row++ {
			for col := 0; col < 8; col++ {
				buf[row*8+col] = 5 * rub.state[row*8+col]
				buf[row*8+col] += 3 * rub.state[((row+1)%8)*8+col]
				buf[row*8+col] += 4 * rub.state[((row+2)%8)*8+col]
				buf[row*8+col] += 3 * rub.state[((row+3)%8)*8+col]
				buf[row*8+col] += 6 * rub.state[((row+4)%8)*8+col]
				buf[row*8+col] += 2 * rub.state[((row+5)%8)*8+col]
				buf[row*8+col] += rub.state[((row+6)%8)*8+col]
				buf[row*8+col] += rub.state[((row+7)%8)*8+col]
				buf[row*8+col] %= p
			}
		}
		// MixRows
		for row := 0; row < 8; row++ {
			for col := 0; col < 8; col++ {
				rub.state[row*8+col] = 5 * buf[row*8+col]
				rub.state[row*8+col] += 3 * buf[row*8+(col+1)%8]
				rub.state[row*8+col] += 4 * buf[row*8+(col+2)%8]
				rub.state[row*8+col] += 3 * buf[row*8+(col+3)%8]
				rub.state[row*8+col] += 6 * buf[row*8+(col+4)%8]
				rub.state[row*8+col] += 2 * buf[row*8+(col+5)%8]
				rub.state[row*8+col] += buf[row*8+(col+6)%8]
				rub.state[row*8+col] += buf[row*8+(col+7)%8]
				rub.state[row*8+col] %= p
			}
		}
	} else {
		panic("Invalid block size!")
	}
}

func (rub *rubato) sBoxFeistel() {
	p := rub.params.GetModulus()
	blockSize := rub.params.GetBlockSize()
	buf := make(sym.Block, blockSize)

	for i := 0; i < blockSize; i++ {
		buf[i] = rub.state[i]
	}

	for i := 1; i < blockSize; i++ {
		rub.state[i] = (buf[i] + buf[i-1]*buf[i-1]) % p
	}
}

func (rub *rubato) addGaussianNoise() {
	gs := rub.sampler
	plainModulus := rub.p

	var coFloat float64
	var coInt, sign uint64

	outputSize := len(rub.state) - 4
	for i := 0; i < outputSize; i++ {
		for {
			coFloat, sign = gs.NormFloat64()

			if coInt = uint64(coFloat*gs.X.Sigma + 0.5); coInt <= uint64(gs.X.Bound) {
				break
			}
		}

		a := rub.state[i] + ((coInt * sign) | (plainModulus-coInt)*(sign^1))
		rub.state[i] = ring.CRed(a, plainModulus)
	}
}
