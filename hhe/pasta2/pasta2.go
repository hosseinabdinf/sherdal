package pasta2

import (
	"fmt"
	"sync"

	"github.com/hosseinabdinf/sherdal/pkg"

	"github.com/hosseinabdinf/sherdal/ske"
	sympasta2 "github.com/hosseinabdinf/sherdal/ske/pasta2"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

type Pasta2 struct {
	config   Config
	rt       *pkg.BGVRuntime
	fv       *pkg.FVPasta2Evaluator
	key      []*rlwe.Ciphertext
	clearKey []uint64
}

func NewPasta2(cfg Config) (*Pasta2, error) {
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

	fv, err := pkg.NewFVPasta2Evaluator(rt, cfg.SymmetricParams)
	if err != nil {
		return nil, err
	}

	return &Pasta2{config: cfg, rt: rt, fv: fv}, nil
}

// NewPasta2WithConfig creates a Pasta2 instance using the given parallel config
// for the underlying FV evaluator.
func NewPasta2WithConfig(cfg Config, parallelCfg pkg.ParallelConfig) (*Pasta2, error) {
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

	fv, err := pkg.NewFVPasta2EvaluatorWithConfig(rt, cfg.SymmetricParams, parallelCfg)
	if err != nil {
		return nil, err
	}

	return &Pasta2{config: cfg, rt: rt, fv: fv}, nil
}

func (p *Pasta2) EncryptSymmetricKey(key []uint64) error {
	encryptedKey, err := p.fv.EncryptKey(key)
	if err != nil {
		return err
	}
	p.key = encryptedKey
	p.clearKey = append([]uint64(nil), key...)
	return nil
}

func (p *Pasta2) EvalKeystream(nonces [][]byte) ([]*rlwe.Ciphertext, error) {
	if p.key == nil {
		return nil, fmt.Errorf("symmetric key is not encrypted")
	}
	return p.fv.Crypt(nonces, p.key)
}

func (p *Pasta2) DecryptKeystream(ciphertexts []*rlwe.Ciphertext, lanes int) ([][]uint64, error) {
	return p.rt.DecryptOutputs(ciphertexts, lanes)
}

func (p *Pasta2) DecryptTransciphered(ciphertexts []*rlwe.Ciphertext, plainSize int) ([]uint64, error) {
	blockWidth := p.config.SymmetricParams.BlockSize
	numBlocks := ske.CeilDiv(plainSize, blockWidth)
	outputs, err := p.rt.DecryptOutputs(ciphertexts, numBlocks)
	if err != nil {
		return nil, err
	}
	return pkg.FlattenDecryptedBlocks(outputs, blockWidth, plainSize), nil
}

func (p *Pasta2) Decrypt(ciphertexts []*rlwe.Ciphertext, plainSize int) ([]uint64, error) {
	return p.DecryptTransciphered(ciphertexts, plainSize)
}

func (p *Pasta2) Runtime() *pkg.BGVRuntime {
	return p.rt
}

func (p *Pasta2) HalfBootSpec() pkg.LegacyHalfBootParameters {
	return p.config.halfBootSpec()
}

func (p *Pasta2) ModDownPlan() pkg.ModDownPlan {
	return p.config.modDownPlan()
}

func (p *Pasta2) NewHalfBootstrapper() (*pkg.HalfBootstrapper, error) {
	spec := p.HalfBootSpec()
	if p.config.UseResidualBGV {
		return pkg.NewHalfBootstrapperWithKeys(spec, p.rt.SecretKey(), p.rt.PublicKey())
	}
	return pkg.NewHalfBootstrapper(spec)
}

func (p *Pasta2) NewBridge() (*pkg.RtFBridge, error) {
	return pkg.NewRtFBridge(p.rt, p.HalfBootSpec())
}

func (p *Pasta2) NewSlotToCoeffTransformer() (*pkg.SlotToCoeffTransformer, error) {
	return pkg.NewSlotToCoeffTransformer(p.rt, p.rt.LogMaxSlots(), p.ModDownPlan().StCModDown)
}

// EvalKeystreamCoeffs evaluates the Pasta2 keystream and then applies the
// slot-to-coefficient transformation to each output ciphertext.
func (p *Pasta2) EvalKeystreamCoeffs(nonces [][]byte) ([]*rlwe.Ciphertext, error) {
	cts, err := p.EvalKeystream(nonces)
	if err != nil {
		return nil, err
	}
	transformer, err := p.NewSlotToCoeffTransformer()
	if err != nil {
		return nil, err
	}
	return transformer.TransformAll(cts)
}

// Transcipher runs the full RtF transciphering pipeline.
func (p *Pasta2) Transcipher(values []float64, nonces [][]byte) (*pkg.TranscipherResult, error) {
	if !p.config.UseResidualBGV {
		return nil, fmt.Errorf("Transcipher requires UseResidualBGV=true")
	}
	if p.clearKey == nil {
		return nil, fmt.Errorf("symmetric key is not encrypted")
	}
	if len(values) == 0 || len(values)%2 != 0 {
		return nil, fmt.Errorf("values length must be a non-zero even number")
	}
	if len(values) != len(nonces) {
		return nil, fmt.Errorf("values length %d must match nonce count %d", len(values), len(nonces))
	}

	type keystreamResult struct {
		cts []*rlwe.Ciphertext
		err error
	}

	keystreamCh := make(chan keystreamResult, 1)
	keystreamCoeffCh := make(chan keystreamResult, 1)
	plainCh := make(chan []uint64, 1)

	go func() {
		cts, err := p.EvalKeystream(nonces)
		keystreamCh <- keystreamResult{cts, err}
	}()

	go func() {
		cts, err := p.EvalKeystreamCoeffs(nonces)
		keystreamCoeffCh <- keystreamResult{cts, err}
	}()

	go func() {
		plainCh <- p.plainKeystreamComponent(nonces)
	}()

	// Collect concurrent results.
	ksRes := <-keystreamCh
	ksCoeffRes := <-keystreamCoeffCh
	plainVals := <-plainCh

	if ksRes.err != nil {
		return nil, fmt.Errorf("eval keystream: %w", ksRes.err)
	}
	if ksCoeffRes.err != nil {
		return nil, fmt.Errorf("eval keystream coeffs: %w", ksCoeffRes.err)
	}

	keystream := ksRes.cts
	keystreamCoeffs := ksCoeffRes.cts
	packedKeystream := pkg.PackKeystreamComponent(plainVals, p.HalfBootSpec().LogN)

	bridge, err := p.NewBridge()
	if err != nil {
		return nil, err
	}
	halfBootstrapper, err := p.NewHalfBootstrapper()
	if err != nil {
		return nil, err
	}

	packedValues := pkg.PackDataToCoefficients(values, p.HalfBootSpec().LogN, len(values))
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
		Runtime:          p.rt,
		Keystream:        keystream,
		KeystreamCoeffs:  keystreamCoeffs,
		ClientPlaintext:  clientPlaintext,
		HalfBootInput:    halfBootInput,
		HalfBootstrapper: halfBootstrapper,
		HalfBootReal:     halfBootReal,
		HalfBootImag:     halfBootImag,
	}, nil
}

// plainKeystreamComponent evaluates the plain Pasta2 cipher for each nonce and
// returns the first keystream word per lane.
func (p *Pasta2) plainKeystreamComponent(nonces [][]byte) []uint64 {
	out := make([]uint64, len(nonces))
	var wg sync.WaitGroup
	for i, nonce := range nonces {
		wg.Add(1)
		go func(i int, nonce []byte) {
			defer wg.Done()
			sym := sympasta2.NewPasta2(p.clearKey, p.config.SymmetricParams)
			out[i] = sym.KeyStream(nonce[:ske.NonceSize], nonce[ske.NonceSize:])[0]
		}(i, nonce)
	}
	wg.Wait()
	return out
}

func (p *Pasta2) TranscipherSymCiphertext(ciphertext []uint64, nonce []byte) ([]*rlwe.Ciphertext, error) {
	if p.key == nil {
		return nil, fmt.Errorf("symmetric key is not encrypted")
	}
	blockWidth := p.config.SymmetricParams.BlockSize
	numBlocks := ske.CeilDiv(len(ciphertext), blockWidth)

	// In Pasta2, nonces are nonce/counter seeds of length 2*ske.NonceSize (16 bytes).
	// We expand nonce to multiple blocks, each block having counter = block index.
	nonceCounterSeeds := make([][]byte, numBlocks)
	for b := 0; b < numBlocks; b++ {
		nonceCounterSeeds[b] = sympasta2.NonceCounterSeed(nonce, uint64(b))
	}

	packed := pkg.PackCiphertextBlocks(ciphertext, blockWidth, p.rt.Slots())
	keystream, err := p.fv.Crypt(nonceCounterSeeds, p.key)
	if err != nil {
		return nil, err
	}
	return pkg.SubtractPackedPlain(p.rt, keystream, packed)
}
