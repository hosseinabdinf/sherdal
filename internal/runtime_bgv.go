package internal

import (
	"fmt"
	"sherdal/applications/configs"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// BGVRuntime owns the common BGV objects used by the modular evaluation layer.
type BGVRuntime struct {
	params    bgv.Parameters
	encoder   *bgv.Encoder
	evaluator *bgv.Evaluator
	encryptor *rlwe.Encryptor
	decryptor *rlwe.Decryptor

	sk  *rlwe.SecretKey
	pk  *rlwe.PublicKey
	rlk *rlwe.RelinearizationKey
	evk *rlwe.MemEvaluationKeySet
}

func NewBGVRuntime(literal bgv.ParametersLiteral) (*BGVRuntime, error) {
	params, err := bgv.NewParametersFromLiteral(literal)
	if err != nil {
		return nil, fmt.Errorf("new BGV parameters: %w", err)
	}

	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	rlk := kgen.GenRelinearizationKeyNew(sk)
	evk := rlwe.NewMemEvaluationKeySet(rlk)

	return &BGVRuntime{
		params:    params,
		encoder:   bgv.NewEncoder(params),
		evaluator: bgv.NewEvaluator(params, evk, true),
		encryptor: bgv.NewEncryptor(params, pk),
		decryptor: bgv.NewDecryptor(params, sk),
		sk:        sk,
		pk:        pk,
		rlk:       rlk,
		evk:       evk,
	}, nil
}

func NewDefaultBGVRuntime(logN int, plainModulus uint64) (*BGVRuntime, error) {
	literal, err := DefaultBGVParametersLiteral(logN, plainModulus)
	if err != nil {
		return nil, err
	}
	return NewBGVRuntime(literal)
}

func NewAlignedBGVRuntime(spec LegacyHalfBootParameters) (*BGVRuntime, error) {
	literal := bgv.ParametersLiteral{
		LogN:             spec.LogN,
		Q:                append([]uint64(nil), spec.ResidualModuli...),
		P:                append([]uint64(nil), spec.KeySwitchModuli...),
		PlaintextModulus: spec.PlainModulus,
	}
	return NewBGVRuntime(literal)
}

func DefaultBGVParametersLiteral(logN int, plainModulus uint64) (bgv.ParametersLiteral, error) {
	var literal bgv.ParametersLiteral

	switch logN {
	case 12:
		literal = configs.BGVParamsN12QP109
	case 13:
		literal = configs.BGVParamsN13QP218
	case 14:
		literal = configs.BGVParamsN14QP438
	case 15:
		literal = configs.BGVParamsN15QP880
	default:
		return bgv.ParametersLiteral{}, fmt.Errorf("unsupported default BGV logN %d", logN)
	}

	literal.PlaintextModulus = plainModulus
	return literal, nil
}

func (rt *BGVRuntime) Parameters() bgv.Parameters {
	return rt.params
}

func (rt *BGVRuntime) Slots() int {
	return rt.params.MaxSlots()
}

func (rt *BGVRuntime) LogMaxSlots() int {
	return rt.params.LogMaxSlots()
}

func (rt *BGVRuntime) SecretKey() *rlwe.SecretKey {
	return rt.sk
}

func (rt *BGVRuntime) PublicKey() *rlwe.PublicKey {
	return rt.pk
}

func (rt *BGVRuntime) EvaluationKeys() *rlwe.MemEvaluationKeySet {
	return rt.evk
}

func (rt *BGVRuntime) DecryptUint(ciphertext *rlwe.Ciphertext) ([]uint64, error) {
	values := make([]uint64, rt.Slots())
	if err := rt.encoder.Decode(rt.decryptor.DecryptNew(ciphertext), values); err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	return values, nil
}

func (rt *BGVRuntime) DecryptOutputs(ciphertexts []*rlwe.Ciphertext, lanes int) ([][]uint64, error) {
	if lanes < 0 || lanes > rt.Slots() {
		return nil, fmt.Errorf("invalid lane count %d", lanes)
	}

	outputs := make([][]uint64, lanes)
	for lane := 0; lane < lanes; lane++ {
		outputs[lane] = make([]uint64, len(ciphertexts))
	}

	for i, ciphertext := range ciphertexts {
		values, err := rt.DecryptUint(ciphertext)
		if err != nil {
			return nil, err
		}
		for lane := 0; lane < lanes; lane++ {
			outputs[lane][i] = values[lane]
		}
	}

	return outputs, nil
}

func (rt *BGVRuntime) encodeUint(values []uint64) (*rlwe.Plaintext, error) {
	plaintext := bgv.NewPlaintext(rt.params, rt.params.MaxLevel())
	if err := rt.encoder.Encode(values, plaintext); err != nil {
		return nil, fmt.Errorf("encode plaintext: %w", err)
	}
	return plaintext, nil
}

func (rt *BGVRuntime) encryptUint(values []uint64) (*rlwe.Ciphertext, error) {
	plaintext, err := rt.encodeUint(values)
	if err != nil {
		return nil, err
	}

	ciphertext, err := rt.encryptor.EncryptNew(plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt plaintext: %w", err)
	}

	return ciphertext, nil
}
