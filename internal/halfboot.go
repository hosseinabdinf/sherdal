package internal

import (
	"fmt"
	"math"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// HalfBootstrapRuntime owns the v6 aes_bootstrapping objects derived from a legacy RtF preset.
type HalfBootstrapRuntime struct {
	Spec         LegacyHalfBootParameters
	Residual     ckks.Parameters
	Parameters   bootstrapping.Parameters
	SecretKey    *rlwe.SecretKey
	PublicKey    *rlwe.PublicKey
	Encoder      *ckks.Encoder
	Encryptor    *rlwe.Encryptor
	Decryptor    *rlwe.Decryptor
	Bootstrapper *bootstrapping.Evaluator
	Keys         *bootstrapping.EvaluationKeys
}

func NewHalfBootstrapRuntime(spec LegacyHalfBootParameters) (*HalfBootstrapRuntime, error) {
	return NewHalfBootstrapRuntimeWithKeys(spec, nil, nil)
}

func NewHalfBootstrapRuntimeWithKeys(spec LegacyHalfBootParameters, sk *rlwe.SecretKey, pk *rlwe.PublicKey) (*HalfBootstrapRuntime, error) {
	residual, err := spec.ResidualParameters()
	if err != nil {
		return nil, err
	}

	params, err := spec.BootstrappingParameters()
	if err != nil {
		return nil, err
	}

	kgen := ckks.NewKeyGenerator(residual)
	if sk == nil {
		sk = kgen.GenSecretKeyWithHammingWeightNew(spec.H)
	}
	if pk == nil {
		pk = kgen.GenPublicKeyNew(sk)
	}
	keys, _, err := params.GenEvaluationKeys(sk)
	if err != nil {
		return nil, fmt.Errorf("generate aes_bootstrapping evaluation keys: %w", err)
	}

	bootstrapper, err := bootstrapping.NewEvaluator(params, keys)
	if err != nil {
		return nil, fmt.Errorf("new aes_bootstrapping evaluator: %w", err)
	}

	return &HalfBootstrapRuntime{
		Spec:         spec,
		Residual:     residual,
		Parameters:   params,
		SecretKey:    sk,
		PublicKey:    pk,
		Encoder:      ckks.NewEncoder(residual),
		Encryptor:    ckks.NewEncryptor(residual, pk),
		Decryptor:    ckks.NewDecryptor(residual, sk),
		Bootstrapper: bootstrapper,
		Keys:         keys,
	}, nil
}

// HalfBootstrapper mirrors the _old halfboot stage on top of the public v6 APIs.
type HalfBootstrapper struct {
	runtime *HalfBootstrapRuntime
}

func NewHalfBootstrapper(spec LegacyHalfBootParameters) (*HalfBootstrapper, error) {
	return NewHalfBootstrapperWithKeys(spec, nil, nil)
}

func NewHalfBootstrapperWithKeys(spec LegacyHalfBootParameters, sk *rlwe.SecretKey, pk *rlwe.PublicKey) (*HalfBootstrapper, error) {
	runtime, err := NewHalfBootstrapRuntimeWithKeys(spec, sk, pk)
	if err != nil {
		return nil, err
	}
	return &HalfBootstrapper{runtime: runtime}, nil
}

func (hb *HalfBootstrapper) Runtime() *HalfBootstrapRuntime {
	return hb.runtime
}

func (hb *HalfBootstrapper) HalfBoot(ct *rlwe.Ciphertext) (ctReal, ctImag *rlwe.Ciphertext, err error) {
	prepared, err := hb.prepareInput(ct)
	if err != nil {
		return nil, nil, err
	}

	modUp, err := hb.runtime.Bootstrapper.ModUp(prepared)
	if err != nil {
		return nil, nil, fmt.Errorf("mod up: %w", err)
	}

	ctReal, ctImag, err = hb.runtime.Bootstrapper.CoeffsToSlots(modUp)
	if err != nil {
		return nil, nil, fmt.Errorf("coeffs to slots: %w", err)
	}

	if ctReal, err = hb.runtime.Bootstrapper.EvalMod(ctReal); err != nil {
		return nil, nil, fmt.Errorf("eval mod real: %w", err)
	}

	if ctImag != nil {
		if ctImag, err = hb.runtime.Bootstrapper.EvalMod(ctImag); err != nil {
			return nil, nil, fmt.Errorf("eval mod imag: %w", err)
		}
	}

	return ctReal, ctImag, nil
}

func (hb *HalfBootstrapper) prepareInput(ct *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	prepared := ct.CopyNew()
	eval := hb.runtime.Bootstrapper.Evaluator
	prescale := rlwe.NewScale(hb.runtime.Spec.Prescale())

	for prepared.Level() > 1 {
		eval.DropLevel(prepared, 1)
	}

	if prepared.Level() == 1 {
		if err := eval.SetScale(prepared, prescale); err != nil {
			return nil, fmt.Errorf("set input scale: %w", err)
		}
		for prepared.Level() > 0 {
			eval.DropLevel(prepared, 1)
		}
	} else {
		for prepared.Level() > 0 {
			eval.DropLevel(prepared, 1)
		}

		if prescale.Cmp(prepared.Scale) < 0 {
			return nil, fmt.Errorf("ciphertext scale %0.4f exceeds halfboot prescale %0.4f", prepared.Scale.Float64(), prescale.Float64())
		}

		ratio := prescale.Div(prepared.Scale).Float64()
		scalar := uint64(math.Round(ratio))
		if scalar > 1 {
			if err := eval.ScaleUp(prepared, rlwe.NewScale(scalar), prepared); err != nil {
				return nil, fmt.Errorf("scale input up: %w", err)
			}
		}
	}

	return prepared, nil
}
