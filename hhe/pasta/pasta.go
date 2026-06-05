package pasta

import (
	"fmt"
	"sync"

	"github.com/hosseinabdinf/sherdal/pkg"

	"github.com/hosseinabdinf/sherdal/ske"
	sympasta "github.com/hosseinabdinf/sherdal/ske/pasta"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

type Pasta struct {
	config   Config
	rt       *pkg.BGVRuntime
	fv       *pkg.FVPastaEvaluator
	key      []*rlwe.Ciphertext
	clearKey []uint64
}

func NewPasta(cfg Config) (*Pasta, error) {
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

	fv, err := pkg.NewFVPastaEvaluator(rt, cfg.SymmetricParams)
	if err != nil {
		return nil, err
	}

	return &Pasta{config: cfg, rt: rt, fv: fv}, nil
}

// NewPastaWithConfig creates a Pasta instance using the given parallel config
// for the underlying FV evaluator. This enables parallelized roundData,
// pastaLinLayer, cubeState, feistelState, and addRoundKey operations.
func NewPastaWithConfig(cfg Config, parallelCfg pkg.ParallelConfig) (*Pasta, error) {
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

	fv, err := pkg.NewFVPastaEvaluatorWithConfig(rt, cfg.SymmetricParams, parallelCfg)
	if err != nil {
		return nil, err
	}

	return &Pasta{config: cfg, rt: rt, fv: fv}, nil
}

func (p *Pasta) EncryptSymmetricKey(key []uint64) error {
	encryptedKey, err := p.fv.EncryptKey(key)
	if err != nil {
		return err
	}
	p.key = encryptedKey
	p.clearKey = append([]uint64(nil), key...)
	return nil
}

func (p *Pasta) EvalKeystream(nonces [][]byte, counter []byte) ([]*rlwe.Ciphertext, error) {
	if p.key == nil {
		return nil, fmt.Errorf("symmetric key is not encrypted")
	}
	return p.fv.Crypt(nonces, counter, p.key)
}

func (p *Pasta) DecryptKeystream(ciphertexts []*rlwe.Ciphertext, lanes int) ([][]uint64, error) {
	return p.rt.DecryptOutputs(ciphertexts, lanes)
}

func (p *Pasta) DecryptTransciphered(ciphertexts []*rlwe.Ciphertext, plainSize int) ([]uint64, error) {
	blockWidth := p.config.SymmetricParams.BlockSize
	numBlocks := ske.CeilDiv(plainSize, blockWidth)
	outputs, err := p.rt.DecryptOutputs(ciphertexts, numBlocks)
	if err != nil {
		return nil, err
	}
	return pkg.FlattenDecryptedBlocks(outputs, blockWidth, plainSize), nil
}

func (p *Pasta) Decrypt(ciphertexts []*rlwe.Ciphertext, plainSize int) ([]uint64, error) {
	return p.DecryptTransciphered(ciphertexts, plainSize)
}

func (p *Pasta) Runtime() *pkg.BGVRuntime {
	return p.rt
}

func (p *Pasta) HalfBootSpec() pkg.LegacyHalfBootParameters {
	return p.config.halfBootSpec()
}

func (p *Pasta) ModDownPlan() pkg.ModDownPlan {
	return p.config.modDownPlan()
}

func (p *Pasta) NewHalfBootstrapper() (*pkg.HalfBootstrapper, error) {
	spec := p.HalfBootSpec()
	if p.config.UseResidualBGV {
		return pkg.NewHalfBootstrapperWithKeys(spec, p.rt.SecretKey(), p.rt.PublicKey())
	}
	return pkg.NewHalfBootstrapper(spec)
}

func (p *Pasta) NewBridge() (*pkg.RtFBridge, error) {
	return pkg.NewRtFBridge(p.rt, p.HalfBootSpec())
}

func (p *Pasta) NewSlotToCoeffTransformer() (*pkg.SlotToCoeffTransformer, error) {
	return pkg.NewSlotToCoeffTransformer(p.rt, p.rt.LogMaxSlots(), p.ModDownPlan().StCModDown)
}

// EvalKeystreamCoeffs evaluates the PASTA keystream and then applies the
// slot-to-coefficient transformation to each output ciphertext.
//
// The slot-to-coefficient transform for each ciphertext is independent, so
// TransformAll runs them in parallel when a parallel config is active.
func (p *Pasta) EvalKeystreamCoeffs(nonces [][]byte, counter []byte) ([]*rlwe.Ciphertext, error) {
	cts, err := p.EvalKeystream(nonces, counter)
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
//
// Parallelism applied here:
//
//  1. EvalKeystream (raw keystream for subtraction) and EvalKeystreamCoeffs
//     (coefficient-domain keystream for the half-boot input) are launched as
//     concurrent goroutines. In the original code both pipelines were sequential
//     AND EvalKeystream was called twice (once directly, once inside
//     EvalKeystreamCoeffs). Now the FV cipher runs only once per pipeline, and
//     both pipelines run simultaneously.
//
//  2. plainKeystreamComponent (pure symmetric-cipher CPU work per nonce) runs
//     concurrently with the HE pipelines above.
//
//  3. NewBridge and NewHalfBootstrapper are sequential (parameter setup), but
//     they are overlapped with the goroutines above.
func (p *Pasta) Transcipher(values []float64, nonces [][]byte, counter []byte) (*pkg.TranscipherResult, error) {
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

	// ── Concurrent phase ─────────────────────────────────────────────────────
	// Three independent tasks run simultaneously:
	//   A. EvalKeystream        — HE keystream for the final subtraction
	//   B. EvalKeystreamCoeffs  — HE keystream in coefficient domain (for half-boot input)
	//   C. plainKeystreamComponent — plain symmetric keystream (CPU-only)
	//
	// Previously EvalKeystream was invoked twice (once directly, once inside
	// EvalKeystreamCoeffs), paying the full cipher cost twice. Now each runs
	// exactly once, and all three run in parallel.

	type keystreamResult struct {
		cts []*rlwe.Ciphertext
		err error
	}

	keystreamCh := make(chan keystreamResult, 1)
	keystreamCoeffCh := make(chan keystreamResult, 1)
	plainCh := make(chan []uint64, 1)

	go func() {
		cts, err := p.EvalKeystream(nonces, counter)
		keystreamCh <- keystreamResult{cts, err}
	}()

	go func() {
		cts, err := p.EvalKeystreamCoeffs(nonces, counter)
		keystreamCoeffCh <- keystreamResult{cts, err}
	}()

	go func() {
		plainCh <- p.plainKeystreamComponent(nonces, counter)
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

	// ── Sequential phase — data-dependent steps ───────────────────────────────

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

// plainKeystreamComponent evaluates the plain PASTA cipher for each nonce and
// returns the first keystream word per lane.
//
// sympasta.NewPasta is stateless after construction; each goroutine creates its
// own instance, so there is no shared mutable state. All lanes run in parallel.
func (p *Pasta) plainKeystreamComponent(nonces [][]byte, counter []byte) []uint64 {
	out := make([]uint64, len(nonces))
	var wg sync.WaitGroup
	for i, nonce := range nonces {
		wg.Add(1)
		go func(i int, nonce []byte) {
			defer wg.Done()
			sym := sympasta.NewPasta(p.clearKey, p.config.SymmetricParams)
			out[i] = sym.KeyStream(nonce, counter)[0]
		}(i, nonce)
	}
	wg.Wait()
	return out
}

func (p *Pasta) TranscipherSymCiphertext(ciphertext []uint64, nonce []byte) ([]*rlwe.Ciphertext, error) {
	if p.key == nil {
		return nil, fmt.Errorf("symmetric key is not encrypted")
	}
	blockWidth := p.config.SymmetricParams.BlockSize
	numBlocks := ske.CeilDiv(len(ciphertext), blockWidth)
	nonces := pkg.ExpandNonceBlocks(nonce, numBlocks)
	counters := pkg.ExpandRubatoCounters(numBlocks) // Reusing this as pasta also takes an 8-byte counter
	packed := pkg.PackCiphertextBlocks(ciphertext, blockWidth, p.rt.Slots())
	keystream, err := p.fv.CryptWithCounters(nonces, counters, p.key)
	if err != nil {
		return nil, err
	}
	return pkg.SubtractPackedPlain(p.rt, keystream, packed)
}
