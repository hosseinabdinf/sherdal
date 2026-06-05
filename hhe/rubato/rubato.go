package rubato

import (
	"fmt"

	"github.com/hosseinabdinf/sherdal/pkg"

	"github.com/hosseinabdinf/sherdal/ske"
	symrubato "github.com/hosseinabdinf/sherdal/ske/rubato"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

type Rubato struct {
	config   Config
	rt       *pkg.BGVRuntime
	fv       *pkg.FVRubatoEvaluator
	key      []*rlwe.Ciphertext
	clearKey []uint64
}

func NewRubato(cfg Config) (*Rubato, error) {
	var (
		rt  *pkg.BGVRuntime
		err error
	)
	if cfg.UseResidualBGV {
		rt, err = pkg.NewAlignedBGVRuntime(cfg.halfBootSpec())
	} else {
		rt, err = pkg.NewDefaultBGVRuntime(cfg.BGVLogN, cfg.SymmetricParams.Modulus)
	}
	if err != nil {
		return nil, err
	}

	fv, err := pkg.NewFVRubatoEvaluator(rt, cfg.SymmetricParams)
	if err != nil {
		return nil, err
	}

	return &Rubato{config: cfg, rt: rt, fv: fv}, nil
}

func (r *Rubato) EncryptSymmetricKey(key []uint64) error {
	encryptedKey, err := r.fv.EncryptKey(key)
	if err != nil {
		return err
	}
	r.key = encryptedKey
	r.clearKey = append([]uint64(nil), key...)
	return nil
}

func (r *Rubato) EvalKeystream(nonces [][]byte, counter []byte) ([]*rlwe.Ciphertext, error) {
	if r.key == nil {
		return nil, fmt.Errorf("symmetric key is not encrypted")
	}
	return r.fv.Crypt(nonces, counter, r.key)
}

func (r *Rubato) DecryptKeystream(ciphertexts []*rlwe.Ciphertext, lanes int) ([][]uint64, error) {
	return r.rt.DecryptOutputs(ciphertexts, lanes)
}

func (r *Rubato) DecryptTransciphered(ciphertexts []*rlwe.Ciphertext, plainSize int) ([]uint64, error) {
	blockWidth := r.config.SymmetricParams.BlockSize - 4
	numBlocks := ske.CeilDiv(plainSize, blockWidth)
	outputs, err := r.rt.DecryptOutputs(ciphertexts, numBlocks)
	if err != nil {
		return nil, err
	}
	return pkg.FlattenDecryptedBlocks(outputs, blockWidth, plainSize), nil
}

func (r *Rubato) Decrypt(ciphertexts []*rlwe.Ciphertext, plainSize int) ([]uint64, error) {
	return r.DecryptTransciphered(ciphertexts, plainSize)
}

func (r *Rubato) Runtime() *pkg.BGVRuntime {
	return r.rt
}

func (r *Rubato) HalfBootSpec() pkg.LegacyHalfBootParameters {
	return r.config.halfBootSpec()
}

func (r *Rubato) ModDownPlan() pkg.ModDownPlan {
	return r.config.modDownPlan()
}

func (r *Rubato) NewHalfBootstrapper() (*pkg.HalfBootstrapper, error) {
	spec := r.HalfBootSpec()
	if r.config.UseResidualBGV {
		return pkg.NewHalfBootstrapperWithKeys(spec, r.rt.SecretKey(), r.rt.PublicKey())
	}
	return pkg.NewHalfBootstrapper(spec)
}

func (r *Rubato) NewBridge() (*pkg.RtFBridge, error) {
	return pkg.NewRtFBridge(r.rt, r.HalfBootSpec())
}

func (r *Rubato) NewSlotToCoeffTransformer() (*pkg.SlotToCoeffTransformer, error) {
	return pkg.NewSlotToCoeffTransformer(r.rt, r.rt.LogMaxSlots(), r.ModDownPlan().StCModDown)
}

func (r *Rubato) EvalKeystreamCoeffs(nonces [][]byte, counter []byte) ([]*rlwe.Ciphertext, error) {
	cts, err := r.EvalKeystream(nonces, counter)
	if err != nil {
		return nil, err
	}
	transformer, err := r.NewSlotToCoeffTransformer()
	if err != nil {
		return nil, err
	}
	return transformer.TransformAll(cts)
}

func (r *Rubato) Transcipher(values []float64, nonces [][]byte, counter []byte) (*pkg.TranscipherResult, error) {
	if !r.config.UseResidualBGV {
		return nil, fmt.Errorf("Transcipher requires UseResidualBGV=true")
	}
	if r.clearKey == nil {
		return nil, fmt.Errorf("symmetric key is not encrypted")
	}
	if len(values) == 0 || len(values)%2 != 0 {
		return nil, fmt.Errorf("values length must be a non-zero even number")
	}
	if len(values) != len(nonces) {
		return nil, fmt.Errorf("values length %d must match nonce count %d", len(values), len(nonces))
	}

	keystream, err := r.EvalKeystream(nonces, counter)
	if err != nil {
		return nil, err
	}
	keystreamCoeffs, err := r.EvalKeystreamCoeffs(nonces, counter)
	if err != nil {
		return nil, err
	}

	bridge, err := r.NewBridge()
	if err != nil {
		return nil, err
	}
	halfBootstrapper, err := r.NewHalfBootstrapper()
	if err != nil {
		return nil, err
	}

	packedValues := pkg.PackDataToCoefficients(values, r.HalfBootSpec().LogN, len(values))
	packedKeystream := pkg.PackKeystreamComponent(r.plainKeystreamComponent(nonces, counter), r.HalfBootSpec().LogN)
	clientPlaintext, err := bridge.BuildClientPlaintext(packedValues, packedKeystream)
	if err != nil {
		return nil, err
	}

	halfBootInput, err := bridge.BuildHalfBootInputFromPlaintext(clientPlaintext, keystreamCoeffs[0])
	if err != nil {
		return nil, err
	}
	halfBootReal, halfBootImag, err := halfBootstrapper.HalfBoot(halfBootInput)
	if err != nil {
		return nil, err
	}

	return &pkg.TranscipherResult{
		Runtime:          r.rt,
		Keystream:        keystream,
		KeystreamCoeffs:  keystreamCoeffs,
		ClientPlaintext:  clientPlaintext,
		HalfBootInput:    halfBootInput,
		HalfBootstrapper: halfBootstrapper,
		HalfBootReal:     halfBootReal,
		HalfBootImag:     halfBootImag,
	}, nil
}

func (r *Rubato) plainKeystreamComponent(nonces [][]byte, counter []byte) []uint64 {
	sym := symrubato.NewRubato(r.clearKey, r.config.SymmetricParams)
	out := make([]uint64, len(nonces))
	for i, nonce := range nonces {
		out[i] = sym.KeyStream(nonce, counter)[0]
	}
	return out
}

func (r *Rubato) TranscipherSymCiphertext(ciphertext []uint64, nonce []byte) ([]*rlwe.Ciphertext, error) {
	if r.key == nil {
		return nil, fmt.Errorf("symmetric key is not encrypted")
	}
	blockWidth := r.config.SymmetricParams.BlockSize - 4
	numBlocks := ske.CeilDiv(len(ciphertext), blockWidth)
	nonces := pkg.ExpandNonceBlocks(nonce, numBlocks)
	counters := pkg.ExpandRubatoCounters(numBlocks)
	packed := pkg.PackCiphertextBlocks(ciphertext, blockWidth, r.rt.Slots())
	keystream, err := r.fv.CryptWithCounters(nonces, counters, r.key)
	if err != nil {
		return nil, err
	}
	return pkg.SubtractPackedPlain(r.rt, keystream, packed)
}
