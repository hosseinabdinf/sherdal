package pasta

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/bits"

	sym "github.com/hosseinabdinf/sherdal/ske"
	"github.com/hosseinabdinf/sherdal/utils"

	"golang.org/x/crypto/sha3"
)

type Pasta interface {
	NewEncryptor() Encryptor
	KeyStream(nonce []byte, counter []byte) sym.Block
}

type pasta struct {
	params       Parameter
	shake        sha3.ShakeHash
	secretKey    sym.Key
	state1       sym.Block
	state2       sym.Block
	p            uint64
	maxPrimeSize uint64
}

func newPasta(secretKey sym.Key, params Parameter) (*pasta, error) {
	if len(secretKey) != params.GetKeySize() {
		return nil, fmt.Errorf("invalid key length: got %d, want %d", len(secretKey), params.GetKeySize())
	}

	mps := uint64(0)
	prime := params.Modulus
	for prime > 0 {
		mps++
		prime >>= 1
	}
	mps = (1 << mps) - 1

	return &pasta{
		params:       params,
		shake:        nil,
		secretKey:    sym.CloneKey(secretKey),
		state1:       make(sym.Block, params.GetBlockSize()),
		state2:       make(sym.Block, params.GetBlockSize()),
		p:            params.GetModulus(),
		maxPrimeSize: mps,
	}, nil
}

// GenerateSymKey takes the parameter set and generate a secure symmetric key
func GenerateSymKey(params Parameter) (key sym.Key) {
	key = make(sym.Key, params.KeySize)

	for i := 0; i < params.KeySize; i++ {
		key[i] = utils.SampleZq(rand.Reader, params.Modulus)
	}

	return
}

// NewPasta return a new instance of pasta cipher
func NewPasta(secretKey sym.Key, params Parameter) Pasta {
	pas, err := NewPastaChecked(secretKey, params)
	if err != nil {
		panic(err)
	}
	return pas
}

func NewPastaChecked(secretKey sym.Key, params Parameter) (Pasta, error) {
	return newPasta(secretKey, params)
}

func (pas *pasta) NewEncryptor() Encryptor {
	return &encryptor{pas: pas.runtime()}
}

func (pas *pasta) runtime() *pasta {
	clone, err := newPasta(pas.secretKey, pas.params)
	if err != nil {
		panic(err)
	}
	return clone
}

// KeyStream generate pasta secretKey stream based on nonce and counter
func (pas *pasta) KeyStream(nonce []byte, counter []byte) sym.Block {
	pas.initShake(nonce, counter)
	ps := pas.params.GetBlockSize()

	// copy half of the secretKey to state1 and the other half to state2
	copy(pas.state1, pas.secretKey[:ps])
	copy(pas.state2, pas.secretKey[ps:])

	// run each round
	for r := 0; r < pas.params.GetRounds(); r++ {
		pas.round(r)
	}

	// final affine with mixing afterward
	pas.linearLayer()
	return sym.CloneBlock(pas.state1)
}

// Round execute pasta cube s_box and f_box per round
func (pas *pasta) round(r int) {
	// Affine `Ai`
	pas.linearLayer()

	// choose the s-boxes
	// Feistel	S`(x)	as the main s-box
	// Cube 	S(x)	to increase the degree
	if r == (pas.params.GetRounds() - 1) {
		// for the last round
		pas.sBoxCube(&pas.state1)
		pas.sBoxCube(&pas.state2)
	} else {
		pas.sBoxFeistel(&pas.state1)
		pas.sBoxFeistel(&pas.state2)
	}
}

// mulMod calculates (a * b) % m.
// Safe and overflow-free for any modulus m < 2^64.
func mulMod(a, b, m uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	_, rem := bits.Div64(hi, lo, m)
	return rem
}

func addMod(a, b, m uint64) uint64 {
	res := a + b
	if res >= m {
		res -= m
	}
	return res
}

// sBoxCube state[i] := (state[i] ^ 3)
func (pas *pasta) sBoxCube(state *sym.Block) {
	for i := 0; i < pas.params.GetBlockSize(); i++ {
		val := (*state)[i]
		square := mulMod(val, val, pas.p)
		(*state)[i] = mulMod(square, val, pas.p)
	}
}

// sBoxFeistel state[i] := {i = 0; state[i];state[i] + (state[i-1] ^ 2)}
func (pas *pasta) sBoxFeistel(state *sym.Block) {
	ps := pas.params.GetBlockSize()
	nState := make(sym.Block, ps)
	nState[0] = (*state)[0]

	for i := 1; i < ps; i++ {
		prevState := (*state)[i-1]
		square := mulMod(prevState, prevState, pas.p)
		nState[i] = addMod(square, (*state)[i], pas.p)
	}

	*state = nState
}

// linearLayer
func (pas *pasta) linearLayer() {
	// matrix multiplication
	pas.matmul(&pas.state1)
	pas.matmul(&pas.state2)
	// state + random field element
	pas.addRC(&pas.state1)
	pas.addRC(&pas.state2)
	// state = state1+state2
	pas.mix()
}

// matmul implementation of matrix multiplication
// requires storage of two row in the matrix
func (pas *pasta) matmul(state *sym.Block) {
	ps := pas.params.GetBlockSize()
	newState := make(sym.Block, ps)
	randVC := pas.getRandomVector(false)
	var currentRow = randVC

	for i := 0; i < ps; i++ {
		for j := 0; j < ps; j++ {
			matMulVal := mulMod(currentRow[j], (*state)[j], pas.p)
			newState[i] = addMod(newState[i], matMulVal, pas.p)
		}
		if i != (ps - 1) {
			currentRow = pas.calculateRow(currentRow, randVC)
		}
	}

	*state = newState
}

// addRC add state with a random field element
func (pas *pasta) addRC(state *sym.Block) {
	ps := pas.params.GetBlockSize()
	for i := 0; i < ps; i++ {
		randElement := pas.generateRandomFieldElement(true)
		(*state)[i] = addMod((*state)[i], randElement, pas.p)
	}
}

// mix add the state1 and state2
func (pas *pasta) mix() {
	ps := pas.params.GetBlockSize()
	for i := 0; i < ps; i++ {
		st1 := pas.state1[i]
		st2 := pas.state2[i]

		sum := addMod(st1, st2, pas.p)
		pas.state1[i] = addMod(sum, st1, pas.p)
		pas.state2[i] = addMod(sum, st2, pas.p)
	}
}

// InitShake function get nonce and counter and combine them as seed for SHAKE128
func (pas *pasta) initShake(nonce []byte, counter []byte) {
	shake := sha3.NewShake128()
	if _, err := shake.Write(nonce); err != nil {
		panic("Failed to init SHAKE128!")
	}
	if _, err := shake.Write(counter); err != nil {
		panic("Failed to init SHAKE128!")
	}
	pas.shake = shake
}

// GenerateRandomFieldElement generate random field element
func (pas *pasta) generateRandomFieldElement(allowZero bool) uint64 {
	var randomByte [8]byte
	for {
		if _, err := pas.shake.Read(randomByte[:]); err != nil {
			panic("SHAKE128 squeeze failed")
		}

		fieldElement := binary.BigEndian.Uint64(randomByte[:]) & pas.maxPrimeSize

		if !allowZero && fieldElement == 0 {
			continue
		}

		if fieldElement < pas.p {
			return fieldElement
		}
	}
}

// getRandomVector generate random Block with the same size as plaintext
func (pas *pasta) getRandomVector(allowZero bool) sym.Block {
	ps := pas.params.GetBlockSize()
	rc := make(sym.Block, ps)
	for i := 0; i < ps; i++ {
		rc[i] = pas.generateRandomFieldElement(allowZero)
	}
	return rc
}

// calculateRow
func (pas *pasta) calculateRow(previousRow, firstRow sym.Block) sym.Block {
	ps := pas.params.GetBlockSize()
	output := make(sym.Block, ps)
	pRow := previousRow[ps-1]

	for j := 0; j < ps; j++ {
		temp := mulMod(firstRow[j], pRow, pas.p)
		if j > 0 {
			temp = addMod(temp, previousRow[j-1], pas.p)
		}
		output[j] = temp
	}
	return output
}
