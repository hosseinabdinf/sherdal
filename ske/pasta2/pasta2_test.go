package pasta2

import (
	"encoding/binary"
	"math/big"
	"reflect"
	"testing"

	sym "github.com/hosseinabdinf/sherdal/ske"
)

func testKey(params Parameter) sym.Key {
	key := make(sym.Key, params.GetKeySize())
	for i := range key {
		key[i] = uint64((i*17 + 3) % int(params.GetModulus()))
	}
	return key
}

func TestParamsValidation(t *testing.T) {
	for _, params := range []Parameter{
		Pasta3Param1614,
		Pasta3Param3215,
		Pasta3Param6015,
		Pasta4Param1614,
		Pasta4Param3215,
		Pasta4Param6015,
	} {
		if err := params.Validate(); err != nil {
			t.Fatalf("valid params rejected: %+v: %v", params, err)
		}
	}

	invalid := []Parameter{
		{Rounds: 3, KeySize: 4, BlockSize: 3, Modulus: 65537},
		{Rounds: 0, KeySize: 2, BlockSize: 1, Modulus: 65537},
		{Rounds: 3, KeySize: 2, BlockSize: 1, Modulus: 65535},
		{Rounds: 3, KeySize: 2, BlockSize: 1, Modulus: 65539},
		{Rounds: 3, KeySize: 2, BlockSize: 1, Modulus: 65537, Mode: Mode(99)},
	}
	for _, params := range invalid {
		if err := params.Validate(); err == nil {
			t.Fatalf("invalid params accepted: %+v", params)
		}
	}
}

func TestFieldAddSubMulInvAgainstBigInt(t *testing.T) {
	params := Pasta4Param6015
	c, err := newPasta2(testKey(params), params)
	if err != nil {
		t.Fatal(err)
	}
	p := new(big.Int).SetUint64(params.GetModulus())
	values := []uint64{0, 1, 2, 65536, params.GetModulus() - 2, params.GetModulus() - 1}
	for _, a := range values {
		for _, b := range values {
			gotAdd := c.add(a, b)
			wantAdd := new(big.Int).Mod(new(big.Int).Add(new(big.Int).SetUint64(a), new(big.Int).SetUint64(b)), p).Uint64()
			if gotAdd != wantAdd {
				t.Fatalf("add(%d,%d)=%d, want %d", a, b, gotAdd, wantAdd)
			}
			gotSub := c.sub(a, b)
			wantSub := new(big.Int).Mod(new(big.Int).Sub(new(big.Int).SetUint64(a), new(big.Int).SetUint64(b)), p).Uint64()
			if gotSub != wantSub {
				t.Fatalf("sub(%d,%d)=%d, want %d", a, b, gotSub, wantSub)
			}
			gotMul := c.mul(a, b)
			wantMul := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).SetUint64(a), new(big.Int).SetUint64(b)), p).Uint64()
			if gotMul != wantMul {
				t.Fatalf("mul(%d,%d)=%d, want %d", a, b, gotMul, wantMul)
			}
		}
		if a != 0 {
			if c.mul(a, c.inv(a)) != 1 {
				t.Fatalf("inverse check failed for %d", a)
			}
		}
	}
}

func TestInstanceGenerationDeterminism(t *testing.T) {
	a, err := NewInstance(Pasta4Param1614)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewInstance(Pasta4Param1614)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("instance generation is not deterministic")
	}
}

func TestSFeistelKnownSmallCases(t *testing.T) {
	params := Parameter{Rounds: 1, KeySize: 6, BlockSize: 3, Modulus: 65537}
	c, err := newPasta2(testKey(params), params)
	if err != nil {
		t.Fatal(err)
	}
	got := c.sFeistelBranch(sym.Block{2, 3, 4})
	want := sym.Block{2, 7, 13}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sFeistel=%v, want %v", got, want)
	}
}

func TestSCubeKnownSmallCases(t *testing.T) {
	params := Parameter{Rounds: 1, KeySize: 6, BlockSize: 3, Modulus: 65537}
	c, err := newPasta2(testKey(params), params)
	if err != nil {
		t.Fatal(err)
	}
	state := sym.Block{2, 3, 65536}
	c.sCubeBranch(state)
	want := sym.Block{8, 27, 65536}
	if !reflect.DeepEqual(state, want) {
		t.Fatalf("sCube=%v, want %v", state, want)
	}
}

func TestMixKnownSmallCases(t *testing.T) {
	params := Parameter{Rounds: 1, KeySize: 4, BlockSize: 2, Modulus: 65537}
	c, err := newPasta2(testKey(params), params)
	if err != nil {
		t.Fatal(err)
	}
	c.mix(sym.Block{1, 65536}, sym.Block{2, 3})
	if !reflect.DeepEqual(c.stateL, sym.Block{4, 1}) {
		t.Fatalf("stateL=%v", c.stateL)
	}
	if !reflect.DeepEqual(c.stateR, sym.Block{5, 5}) {
		t.Fatalf("stateR=%v", c.stateR)
	}
}

func TestKeystreamDeterminismAndCounterChange(t *testing.T) {
	params := Pasta4Param1614
	cipher := NewPasta2(testKey(params), params)
	nonce := make([]byte, 8)
	counter0 := make([]byte, 8)
	counter1 := make([]byte, 8)
	binary.BigEndian.PutUint64(counter1, 1)

	ks0 := cipher.KeyStream(nonce, counter0)
	ks1 := cipher.KeyStream(nonce, counter0)
	if !reflect.DeepEqual(ks0, ks1) {
		t.Fatal("same nonce/counter produced different keystreams")
	}
	ks2 := cipher.KeyStream(nonce, counter1)
	if reflect.DeepEqual(ks0, ks2) {
		t.Fatal("different counters produced identical keystreams")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	params := Pasta4Param1614
	enc := NewPasta2(testKey(params), params).NewEncryptor()
	msg := make(sym.Plaintext, params.GetBlockSize()+7)
	for i := range msg {
		msg[i] = uint64((i * 19) % int(params.GetModulus()))
	}
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ct := enc.EncryptWithNonce(msg, nonce)
	pt := enc.DecryptWithNonce(ct, nonce)
	if !reflect.DeepEqual(pt, msg) {
		t.Fatalf("round trip failed: got %v, want %v", pt, msg)
	}
}

func TestInvalidWordRejected(t *testing.T) {
	params := Pasta4Param1614
	enc := NewPasta2(testKey(params), params).NewEncryptor()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for invalid plaintext word")
		}
	}()
	enc.Encrypt(sym.Plaintext{params.GetModulus()})
}
