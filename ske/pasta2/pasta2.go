package pasta2

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/bits"

	sym "github.com/hosseinabdinf/sherdal/ske"
	"github.com/hosseinabdinf/sherdal/utils"
	utilsmath "github.com/hosseinabdinf/sherdal/utils/math"
	"golang.org/x/crypto/sha3"
)

// Pasta2 represents the Pasta v2 cipher interface
type Pasta2 interface {
	NewEncryptor() Encryptor
	KeyStream(nonce []byte, counter []byte) sym.Block
}

// Instance holds the public random matrices and round constants generated for a parameter set
type Instance struct {
	M        sym.Matrix
	MfL, MfR sym.Matrix
	RcL, RcR sym.Matrix
}

type pasta2 struct {
	params    Parameter
	shake     sha3.ShakeHash
	secretKey sym.Key
	stateL    sym.Block
	stateR    sym.Block
	p         uint64
	bred      []uint64
	m         sym.Matrix
	mfL       sym.Matrix
	mfR       sym.Matrix
	rcL       sym.Matrix
	rcR       sym.Matrix
	mask      uint64
}

// NewInstance constructs a public Pasta2 instance (matrices, round constants) for parameter set validation
func NewInstance(params Parameter) (Instance, error) {
	if err := params.Validate(); err != nil {
		return Instance{}, err
	}
	c, err := newPasta2(make(sym.Key, params.GetKeySize()), params)
	if err != nil {
		return Instance{}, err
	}
	return Instance{
		M:   sym.CloneMatrix(c.m),
		MfL: sym.CloneMatrix(c.mfL),
		MfR: sym.CloneMatrix(c.mfR),
		RcL: sym.CloneMatrix(c.rcL),
		RcR: sym.CloneMatrix(c.rcR),
	}, nil
}

func newPasta2(secretKey sym.Key, params Parameter) (*pasta2, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if len(secretKey) != params.GetKeySize() {
		return nil, fmt.Errorf("invalid key length: got %d, want %d", len(secretKey), params.GetKeySize())
	}
	for i, v := range secretKey {
		if v >= params.GetModulus() {
			return nil, fmt.Errorf("invalid key word at index %d: got %d, want < %d", i, v, params.GetModulus())
		}
	}

	p := params.GetModulus()
	c := &pasta2{
		params:    params,
		secretKey: sym.CloneKey(secretKey),
		stateL:    make(sym.Block, params.GetBlockSize()),
		stateR:    make(sym.Block, params.GetBlockSize()),
		p:         p,
		bred:      utils.BRedParams(p),
		mask:      fieldMask(p),
	}
	if err := c.generateInstance(); err != nil {
		return nil, err
	}
	return c, nil
}

// NonceCounterSeed combines a nonce and counter into a single seed slice
func NonceCounterSeed(nonce []byte, counter uint64) []byte {
	seed := make([]byte, 2*sym.NonceSize)
	copy(seed[:sym.NonceSize], sym.NormalizeNonce(nonce))
	binary.BigEndian.PutUint64(seed[sym.NonceSize:], counter)
	return seed
}

// GenerateSymKey generates a secure symmetric key using random source
func GenerateSymKey(params Parameter) (key sym.Key) {
	if err := params.Validate(); err != nil {
		panic(err)
	}
	key = make(sym.Key, params.KeySize)
	for i := 0; i < params.KeySize; i++ {
		key[i] = utils.SampleZq(rand.Reader, params.Modulus)
	}
	return
}

// NewPasta2 returns a new instance of Pasta2 cipher
func NewPasta2(secretKey sym.Key, params Parameter) Pasta2 {
	pas, err := NewPasta2Checked(secretKey, params)
	if err != nil {
		panic(err)
	}
	return pas
}

// NewPasta2Checked returns a new instance of Pasta2 cipher or an error if parameters validation failed
func NewPasta2Checked(secretKey sym.Key, params Parameter) (Pasta2, error) {
	return newPasta2(secretKey, params)
}

func (c *pasta2) NewEncryptor() Encryptor {
	return &encryptor{pas: c.runtime()}
}

func (c *pasta2) runtime() *pasta2 {
	clone, err := newPasta2(c.secretKey, c.params)
	if err != nil {
		panic(err)
	}
	return clone
}

func (c *pasta2) KeyStream(nonce []byte, counter []byte) sym.Block {
	c.initShake(nonce, counter)
	t := c.params.GetBlockSize()
	copy(c.stateL, c.secretKey[:t])
	copy(c.stateR, c.secretKey[t:])

	c.affine0()
	for q := 0; q < c.params.GetRounds()-1; q++ {
		c.stateL = c.sFeistelBranch(c.stateL)
		c.stateR = c.sFeistelBranch(c.stateR)
		c.affineFixed(q)
	}
	c.sCubeBranch(c.stateL)
	c.sCubeBranch(c.stateR)
	c.affineFixed(c.params.GetRounds() - 1)

	return sym.CloneBlock(c.stateL)
}

func (c *pasta2) initShake(nonce []byte, counter []byte) {
	nonce = sym.NormalizeNonce(nonce)
	if len(counter) == 0 {
		counter = make([]byte, sym.NonceSize)
	}
	if len(counter) != sym.NonceSize {
		panic("invalid counter length")
	}
	shake := sha3.NewShake128()
	if _, err := shake.Write(nonce); err != nil {
		panic("failed to init SHAKE128")
	}
	if _, err := shake.Write(counter); err != nil {
		panic("failed to init SHAKE128")
	}
	c.shake = shake
}

func (c *pasta2) generateInstance() error {
	shake := sha3.NewShake128()
	seed := make([]byte, 16)
	copy(seed[:7], []byte("PASTA2_"))
	seed[7] = byte('0' + c.params.GetRounds())
	binary.BigEndian.PutUint64(seed[8:], c.p)
	if _, err := shake.Write(seed); err != nil {
		return err
	}

	r := c.params.GetRounds()
	t := c.params.GetBlockSize()
	c.rcL = make(sym.Matrix, r)
	c.rcR = make(sym.Matrix, r)
	for q := 0; q < r; q++ {
		c.rcL[q] = c.sampleVecFrom(shake, t, true)
		c.rcR[q] = c.sampleVecFrom(shake, t, true)
	}

	m, err := c.generateMDS(shake)
	if err != nil {
		return err
	}
	c.m = m
	c.mfL = c.generateSequentialMatrix(shake)
	c.mfR = c.generateSequentialMatrix(shake)
	return nil
}

func (c *pasta2) generateMDS(shake sha3.ShakeHash) (sym.Matrix, error) {
	t := c.params.GetBlockSize()
	bitLen := bits.Len64(c.p)
	xBits := bitLen - 7 - 2
	if xBits <= 0 {
		return nil, fmt.Errorf("invalid modulus bit length for MDS generation: %d", bitLen)
	}
	xMask := uint64(1<<xBits) - 1
	yMask := fieldMask(c.p) >> 2
	xs := make(sym.Block, 0, t)
	ys := make(sym.Block, 0, t)
	seenX := make(map[uint64]struct{}, t)
	seenY := make(map[uint64]struct{}, t)

	for len(xs) < t {
		y := c.sampleMaskedFrom(shake, yMask, true)
		if y == 0 {
			continue
		}
		x := y & xMask
		if _, ok := seenX[x]; ok {
			continue
		}
		if _, ok := seenY[y]; ok {
			continue
		}
		seenX[x] = struct{}{}
		seenY[y] = struct{}{}
		xs = append(xs, x)
		ys = append(ys, y)
	}

	m := make(sym.Matrix, t)
	for i := 0; i < t; i++ {
		m[i] = make(sym.Block, t)
		for j := 0; j < t; j++ {
			denom := c.add(xs[i], ys[j])
			if denom == 0 {
				return nil, fmt.Errorf("invalid MDS denominator at row %d column %d", i, j)
			}
			m[i][j] = c.inv(denom)
		}
	}
	return m, nil
}

func (c *pasta2) generateSequentialMatrix(shake sha3.ShakeHash) sym.Matrix {
	t := c.params.GetBlockSize()
	firstRow := c.sampleVecFrom(shake, t, false)
	m := make(sym.Matrix, t)
	m[0] = sym.CloneBlock(firstRow)
	for i := 1; i < t; i++ {
		m[i] = make(sym.Block, t)
		last := m[i-1][t-1]
		for j := 0; j < t; j++ {
			v := c.mul(firstRow[j], last)
			if j > 0 {
				v = c.add(v, m[i-1][j-1])
			}
			m[i][j] = v
		}
	}
	return m
}

func (c *pasta2) affine0() {
	t := c.params.GetBlockSize()
	switch c.params.GetMode() {
	case ModeSpecStrict:
		c0L := c.sampleVec(t, true)
		c0R := c.sampleVec(t, true)
		betaL := c.sampleVec(t, false)
		betaR := c.sampleVec(t, false)
		tmpL := c.hadamard(betaL, c.stateL)
		tmpR := c.hadamard(betaR, c.stateR)
		zL := c.matVec(c.mfL, tmpL)
		zR := c.matVec(c.mfR, tmpR)
		c.addVec(zL, c0L)
		c.addVec(zR, c0R)
		c.mix(zL, zR)
	case ModeCompatCPP:
		betaL := c.sampleVec(t, false)
		betaR := c.sampleVec(t, false)
		c0L := c.sampleVec(t, true)
		c0R := c.sampleVec(t, true)
		zL := c.matVec(c.mfL, c.stateL)
		zR := c.matVec(c.mfR, c.stateR)
		c.hadamardInPlace(zL, betaL)
		c.hadamardInPlace(zR, betaR)
		c.addVec(zL, c0L)
		c.addVec(zR, c0R)
		c.mix(zL, zR)
	default:
		panic("invalid Pasta2 mode")
	}
}

func (c *pasta2) affineFixed(q int) {
	zL := c.matVec(c.m, c.stateL)
	zR := c.matVec(c.m, c.stateR)
	c.addVec(zL, c.rcL[q])
	c.addVec(zR, c.rcR[q])
	c.mix(zL, zR)
}

func (c *pasta2) sFeistelBranch(in sym.Block) sym.Block {
	out := make(sym.Block, len(in))
	if len(in) == 0 {
		return out
	}
	out[0] = in[0]
	for i := 1; i < len(in); i++ {
		out[i] = c.add(in[i], c.square(in[i-1]))
	}
	return out
}

func (c *pasta2) sCubeBranch(state sym.Block) {
	for i := range state {
		state[i] = c.cube(state[i])
	}
}

func (c *pasta2) matVec(m sym.Matrix, x sym.Block) sym.Block {
	out := make(sym.Block, len(m))
	for i := range m {
		var acc uint64
		for j, coeff := range m[i] {
			if coeff == 0 || x[j] == 0 {
				continue
			}
			acc = c.add(acc, c.mul(coeff, x[j]))
		}
		out[i] = acc
	}
	return out
}

func (c *pasta2) addVec(dst, src sym.Block) {
	for i := range dst {
		dst[i] = c.add(dst[i], src[i])
	}
}

func (c *pasta2) hadamard(a, b sym.Block) sym.Block {
	out := make(sym.Block, len(a))
	for i := range a {
		out[i] = c.mul(a[i], b[i])
	}
	return out
}

func (c *pasta2) hadamardInPlace(dst, mask sym.Block) {
	for i := range dst {
		dst[i] = c.mul(dst[i], mask[i])
	}
}

func (c *pasta2) mix(zL, zR sym.Block) {
	for i := range zL {
		sum := c.add(zL[i], zR[i])
		c.stateL[i] = c.add(zL[i], sum)
		c.stateR[i] = c.add(zR[i], sum)
	}
}

func (c *pasta2) sampleVec(size int, allowZero bool) sym.Block {
	return c.sampleVecFrom(c.shake, size, allowZero)
}

func (c *pasta2) sampleVecFrom(shake sha3.ShakeHash, size int, allowZero bool) sym.Block {
	out := make(sym.Block, size)
	for i := range out {
		out[i] = c.sampleFrom(shake, allowZero)
	}
	return out
}

func (c *pasta2) sampleFrom(shake sha3.ShakeHash, allowZero bool) uint64 {
	return c.sampleMaskedFrom(shake, c.mask, allowZero)
}

func (c *pasta2) sampleMaskedFrom(shake sha3.ShakeHash, mask uint64, allowZero bool) uint64 {
	var buf [8]byte
	for {
		if _, err := shake.Read(buf[:]); err != nil {
			panic("SHAKE128 squeeze failed")
		}
		x := binary.BigEndian.Uint64(buf[:]) & mask
		if x >= c.p {
			continue
		}
		if !allowZero && x == 0 {
			continue
		}
		return x
	}
}

func (c *pasta2) add(a, b uint64) uint64 {
	sum, carry := bits.Add64(a, b, 0)
	if carry != 0 || sum >= c.p {
		sum -= c.p
	}
	return sum
}

func (c *pasta2) sub(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return c.p - (b - a)
}

func (c *pasta2) mul(a, b uint64) uint64 {
	return utils.BRed(a, b, c.p, c.bred)
}

func (c *pasta2) square(a uint64) uint64 {
	return c.mul(a, a)
}

func (c *pasta2) cube(a uint64) uint64 {
	return c.mul(c.square(a), a)
}

func (c *pasta2) inv(a uint64) uint64 {
	return utilsmath.ModExp(a, int(c.p-2), c.p)
}

func fieldMask(p uint64) uint64 {
	bitLen := bits.Len64(p)
	if bitLen == 64 {
		return ^uint64(0)
	}
	return uint64(1<<bitLen) - 1
}
