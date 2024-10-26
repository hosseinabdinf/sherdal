package pasta

import (
	"crypto/rand"
	"encoding/binary"
	"golang.org/x/crypto/sha3"
	"math/big"
	"sherdal/hhe/sym"
	"sherdal/utils"
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

// GenerateSymKey takes the parameter set and generate a secure symmetric key
func GenerateSymKey(params Parameter) (key sym.Key) {
	key = make(sym.Key, params.KeySize)

	for i := 0; i < params.KeySize; i++ {
		//key[i] = sampling.RandUint64() % params.PlainModulus
		key[i] = utils.SampleZq(rand.Reader, params.Modulus)
	}

	return
}

// NewPasta return a new instance of pasta cipher
func NewPasta(secretKey sym.Key, params Parameter) Pasta {
	if len(secretKey) != params.GetKeySize() {
		panic("Invalid Key Length!")
	}

	mps := uint64(0) // max prime size
	prime := params.Modulus

	// count the number of valid bits of prime number, using shift to right operation
	for prime > 0 {
		mps++
		prime >>= 1
	}

	// set mps to the maximum value that can be represented with mps bits
	mps = (1 << mps) - 1

	// init empty states
	state1 := make(sym.Block, params.GetBlockSize())
	state2 := make(sym.Block, params.GetBlockSize())

	// create a new pasta instance
	pas := &pasta{
		params:       params,
		shake:        nil,
		secretKey:    secretKey,
		state1:       state1,
		state2:       state2,
		p:            params.GetModulus(),
		maxPrimeSize: mps,
	}
	return pas
}

func (pas *pasta) NewEncryptor() Encryptor {
	return &encryptor{pas: *pas}
}

// prepareOneBlock prepare the first block and call preProcess function
func (pas *pasta) prepareOneBlock() {
	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, uint64(123456789))
	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, uint64(1))
	pas.preProcess(nonce, counter)
}

// preProcess make the XOF and matrices and vectors
func (pas *pasta) preProcess(nonce []byte, counter []byte) {
	numRounds := pas.params.GetRounds()
	pas.initShake(nonce, counter)
	mats1 := make(sym.Vector3D, numRounds+1)
	mats2 := make(sym.Vector3D, numRounds+1)
	rcs1 := make(sym.Matrix, numRounds+1)
	rcs2 := make(sym.Matrix, numRounds+1)

	for r := 0; r <= numRounds; r++ {
		mats1[r] = pas.getRandomMatrix()
		mats2[r] = pas.getRandomMatrix()
		rcs1[r] = pas.getRandomVector(true)
		rcs2[r] = pas.getRandomVector(true)
	}
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
	return pas.state1
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

// sBoxCube state[i] := (state[i] ^ 3)
func (pas *pasta) sBoxCube(state *sym.Block) {
	modulus := new(big.Int).SetUint64(pas.params.GetModulus())
	for i := 0; i < pas.params.GetBlockSize(); i++ {
		// square = state ^ 2 (mod p)
		curState := new(big.Int).SetUint64((*state)[i])
		square := new(big.Int).Mul(curState, curState)
		square.Mod(square, modulus)

		// cube = square * state (mod p)
		cube := square.Mul(square, curState)
		cube.Mod(cube, modulus)

		(*state)[i] = cube.Uint64()
	}
}

// sBoxFeistel state[i] := {i = 0; state[i];state[i] + (state[i-1] ^ 2)}
func (pas *pasta) sBoxFeistel(state *sym.Block) {
	ps := pas.params.GetBlockSize()
	modulus := new(big.Int).SetUint64(pas.params.GetModulus())

	nState := make(sym.Block, ps)
	nState[0] = (*state)[0]

	for i := 1; i < ps; i++ {
		// square = state[i-1] ^ 2 (mod p)
		prevState := new(big.Int).SetUint64((*state)[i-1])
		square := new(big.Int).Mul(prevState, prevState)
		square.Mod(square, modulus)
		curState := new(big.Int).SetUint64((*state)[i])
		//square = square + state[i] (mod p)
		square.Add(square, curState)
		square.Mod(square, modulus)
		// new state = square
		nState[i] = square.Uint64()
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
	modulus := new(big.Int).SetUint64(pas.params.GetModulus())
	newState := make(sym.Block, ps)
	randVC := pas.getRandomVector(false)
	var currentRow = randVC

	for i := 0; i < ps; i++ {
		for j := 0; j < ps; j++ {
			matMulVal := new(big.Int).Mul(big.NewInt(int64(currentRow[j])), big.NewInt(int64((*state)[j])))
			matMulVal.Mod(matMulVal, modulus)

			newState[i] = (newState[i] + matMulVal.Uint64()) % pas.params.Modulus
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
	modulus := new(big.Int).SetUint64(pas.params.GetModulus())

	for i := 0; i < ps; i++ {
		randElement := new(big.Int).SetUint64(pas.generateRandomFieldElement(true))
		curState := new(big.Int).SetUint64((*state)[i])

		curState.Add(curState, randElement)
		curState.Mod(curState, modulus)

		(*state)[i] = curState.Uint64()
	}
}

/*
	(2	1) (state1)
	(1	2) (state2)
*/

// mix add the state1 and state2
func (pas *pasta) mix() {
	ps := pas.params.GetBlockSize()
	modulus := new(big.Int).SetUint64(pas.params.GetModulus())

	// allocate memory for the two state
	st1 := new(big.Int)
	st2 := new(big.Int)

	// adding states
	for i := 0; i < ps; i++ {
		st1.SetUint64(pas.state1[i])
		st2.SetUint64(pas.state2[i])

		// (state1[i] + state2[i]) % pas.p
		sum := new(big.Int).Add(st1, st2)
		sum.Mod(sum, modulus)

		//state1[i] = (state1[i] + sum) % pas.p
		sSt1 := new(big.Int).Add(sum, st1)
		sSt1.Mod(sSt1, modulus)

		//state2[i] = (state2[i] + sum) % pas.p
		sSt2 := new(big.Int).Add(sum, st2)
		sSt2.Mod(sSt2, modulus)

		pas.state1[i] = sSt1.Uint64()
		pas.state2[i] = sSt2.Uint64()
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

/*
[	0	1	0	...	0	]
[	0	0	1	...	0	]
[	.	.	.	...	.	]
[	.	.	.	...	.	]
[	0	0	0	...	1	]
[	r1	r2	r3	...	rt	]
*/

// GetRandomMatrix generate a random invertible matrix
func (pas *pasta) getRandomMatrix() sym.Matrix {
	ps := pas.params.GetBlockSize()
	mat := make(sym.Matrix, ps) // mat[ps][ps]
	for i := range mat {
		mat[i] = make(sym.Block, ps) // mat[i] = [ps]
	}
	mat[0] = pas.getRandomVector(false)
	for j := 1; j < ps; j++ {
		mat[j] = pas.calculateRow(mat[j-1], mat[0])
	}
	return mat
}

// GetRcVector return a vector of random elements, the vector size will be (size+plainSize)
func (pas *pasta) getRcVector(size int) sym.Block {
	ps := pas.params.GetBlockSize()
	rc := make(sym.Block, size+ps)
	for i := 0; i < ps; i++ {
		rc[i] = pas.generateRandomFieldElement(false)
	}
	for i := size; i < (size + ps); i++ {
		rc[i] = pas.generateRandomFieldElement(false)
	}
	return rc
}

// calculateRow
func (pas *pasta) calculateRow(previousRow, firstRow sym.Block) sym.Block {
	ps := pas.params.GetBlockSize()
	modulus := new(big.Int).SetUint64(pas.params.GetModulus())
	output := make(sym.Block, ps)
	// =======================================
	pRow := new(big.Int).SetUint64(previousRow[ps-1])

	for j := 0; j < ps; j++ {
		fRow := new(big.Int).SetUint64(firstRow[j])
		temp := new(big.Int).Mul(fRow, pRow)
		temp.Mod(temp, modulus)
		// update the index row and add the value to the temp
		if j > 0 {
			indexRow := new(big.Int).SetUint64(previousRow[j-1])
			temp.Add(temp, indexRow)
			temp.Mod(temp, modulus)
		}

		output[j] = temp.Uint64()
	}
	return output
}

func (pas *pasta) ShallowCopy() Pasta {
	return &pasta{
		p:            pas.p,
		secretKey:    pas.secretKey,
		maxPrimeSize: pas.maxPrimeSize,
		shake:        pas.shake,
		params:       pas.params,
		state1:       pas.state1,
		state2:       pas.state2,
	}
}
