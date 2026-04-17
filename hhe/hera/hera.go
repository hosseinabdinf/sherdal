package hera

import (
	"fmt"
	"sherdal/internal"
	"sherdal/ske"
	symhera "sherdal/ske/hera"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

type Hera struct {
	config   Config
	rt       *internal.BGVRuntime
	fv       *internal.FVHeraEvaluator
	key      []*rlwe.Ciphertext
	clearKey []uint64
}

func NewHera(cfg Config) (*Hera, error) {
	var (
		rt  *internal.BGVRuntime
		err error
	)
	if cfg.UseResidualBGV {
		rt, err = internal.NewAlignedBGVRuntime(cfg.halfBootSpec())
	} else {
		rt, err = internal.NewDefaultBGVRuntime(cfg.BGVLogN, cfg.SymmetricParams.Modulus)
	}
	if err != nil {
		return nil, err
	}

	fv, err := internal.NewFVHeraEvaluator(rt, cfg.SymmetricParams)
	if err != nil {
		return nil, err
	}

	return &Hera{config: cfg, rt: rt, fv: fv}, nil
}

func (h *Hera) EncryptSymmetricKey(key []uint64) error {
	encryptedKey, err := h.fv.EncryptKey(key)
	if err != nil {
		return err
	}
	h.key = encryptedKey
	h.clearKey = append([]uint64(nil), key...)
	return nil
}

func (h *Hera) EvalKeystream(nonces [][]byte) ([]*rlwe.Ciphertext, error) {
	if h.key == nil {
		return nil, fmt.Errorf("symmetric key is not encrypted")
	}
	return h.fv.Crypt(nonces, h.key)
}

func (h *Hera) DecryptKeystream(ciphertexts []*rlwe.Ciphertext, lanes int) ([][]uint64, error) {
	return h.rt.DecryptOutputs(ciphertexts, lanes)
}

func (h *Hera) DecryptTransciphered(ciphertexts []*rlwe.Ciphertext, plainSize int) ([]uint64, error) {
	blockWidth := h.config.SymmetricParams.BlockSize
	numBlocks := ske.CeilDiv(plainSize, blockWidth)
	outputs, err := h.rt.DecryptOutputs(ciphertexts, numBlocks)
	if err != nil {
		return nil, err
	}
	return internal.FlattenDecryptedBlocks(outputs, blockWidth, plainSize), nil
}

func (h *Hera) Decrypt(ciphertexts []*rlwe.Ciphertext, plainSize int) ([]uint64, error) {
	return h.DecryptTransciphered(ciphertexts, plainSize)
}

func (h *Hera) Runtime() *internal.BGVRuntime {
	return h.rt
}

func (h *Hera) HalfBootSpec() internal.LegacyHalfBootParameters {
	return h.config.halfBootSpec()
}

func (h *Hera) ModDownPlan() internal.ModDownPlan {
	return h.config.modDownPlan()
}

func (h *Hera) NewHalfBootstrapper() (*internal.HalfBootstrapper, error) {
	spec := h.HalfBootSpec()
	if h.config.UseResidualBGV {
		return internal.NewHalfBootstrapperWithKeys(spec, h.rt.SecretKey(), h.rt.PublicKey())
	}
	return internal.NewHalfBootstrapper(spec)
}

func (h *Hera) NewBridge() (*internal.RtFBridge, error) {
	return internal.NewRtFBridge(h.rt, h.HalfBootSpec())
}

func (h *Hera) NewSlotToCoeffTransformer() (*internal.SlotToCoeffTransformer, error) {
	return internal.NewSlotToCoeffTransformer(h.rt, h.config.logFVSlots(), h.ModDownPlan().StCModDown)
}

func (h *Hera) EvalKeystreamCoeffs(nonces [][]byte) ([]*rlwe.Ciphertext, error) {
	cts, err := h.EvalKeystream(nonces)
	if err != nil {
		return nil, err
	}
	transformer, err := h.NewSlotToCoeffTransformer()
	if err != nil {
		return nil, err
	}
	return transformer.TransformAll(cts)
}

func (h *Hera) Transcipher(values []float64, nonces [][]byte) (*internal.TranscipherResult, error) {
	if !h.config.UseResidualBGV {
		return nil, fmt.Errorf("Transcipher requires UseResidualBGV=true")
	}
	if h.clearKey == nil {
		return nil, fmt.Errorf("symmetric key is not encrypted")
	}
	if len(values) == 0 || len(values)%2 != 0 {
		return nil, fmt.Errorf("values length must be a non-zero even number")
	}
	if len(values) != len(nonces) {
		return nil, fmt.Errorf("values length %d must match nonce count %d", len(values), len(nonces))
	}

	keystream, err := h.EvalKeystream(nonces)
	if err != nil {
		return nil, err
	}
	keystreamCoeffs, err := h.EvalKeystreamCoeffs(nonces)
	if err != nil {
		return nil, err
	}

	bridge, err := h.NewBridge()
	if err != nil {
		return nil, err
	}
	halfBootstrapper, err := h.NewHalfBootstrapper()
	if err != nil {
		return nil, err
	}

	packedValues := internal.PackDataToCoefficients(values, h.HalfBootSpec().LogN, len(values))
	packedKeystream := internal.PackKeystreamComponent(h.plainKeystreamComponent(nonces), h.HalfBootSpec().LogN)
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

	return &internal.TranscipherResult{
		Keystream:        keystream,
		KeystreamCoeffs:  keystreamCoeffs,
		ClientPlaintext:  clientPlaintext,
		HalfBootInput:    halfBootInput,
		HalfBootstrapper: halfBootstrapper,
		HalfBootReal:     halfBootReal,
		HalfBootImag:     halfBootImag,
	}, nil
}

func (h *Hera) plainKeystreamComponent(nonces [][]byte) []uint64 {
	sym := symhera.NewHera(h.clearKey, h.config.SymmetricParams)
	out := make([]uint64, len(nonces))
	for i, nonce := range nonces {
		out[i] = sym.KeyStream(nonce)[0]
	}
	return out
}

func (h *Hera) TranscipherSymCiphertext(ciphertext []uint64, nonce []byte) ([]*rlwe.Ciphertext, error) {
	if h.key == nil {
		return nil, fmt.Errorf("symmetric key is not encrypted")
	}
	blockWidth := h.config.SymmetricParams.BlockSize
	numBlocks := ske.CeilDiv(len(ciphertext), blockWidth)
	nonces := internal.ExpandNonceBlocks(nonce, numBlocks)
	packed := internal.PackCiphertextBlocks(ciphertext, blockWidth, h.rt.Slots())
	keystream, err := h.fv.Crypt(nonces, h.key)
	if err != nil {
		return nil, err
	}
	return internal.SubtractPackedPlain(h.rt, keystream, packed)
}
