package cbls

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/bls"
)

const (
	dstG1 = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"
	dstG2 = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
)

const salt32 = "78431268758871967631102412708397" // 32 bytes

func readRandomBytes(n int) []byte {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		panic(err)
	}
	return b
}

func read64RandomBytes() []byte {
	const n = 64
	return readRandomBytes(n)
}

func generateSecretKey() (*bls.PrivateKey[bls.G1], error) {
	b64 := read64RandomBytes()
	pk, err := bls.KeyGen[bls.G1](b64, []byte(salt32), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate (%T): %w", pk, err)
	}
	return pk, nil
}

func unmarshalSecretKey(skBytes []byte) (*bls.PrivateKey[bls.G1], error) {
	sk := new(bls.PrivateKey[bls.G1])
	if err := sk.UnmarshalBinary(skBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret key: %w", err)
	}
	if ok := sk.Validate(); !ok {
		return nil, fmt.Errorf("failed to validate secret key")
	}
	return sk, nil
}

func UnmarshalSecretKeyG1SigG2(skBytes []byte) (*bls.PrivateKey[bls.KeyG1SigG2], error) {
	sk, err := unmarshalSecretKey(skBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret key: %w", err)
	}
	return sk, nil
}

// Sign signs the message with the given private key. Returns compressed signature.
func Sign(sk *bls.PrivateKey[bls.G1], msg []byte) bls.Signature {
	return bls.Sign(sk, msg, func(opts *bls.SignOpts) {
		opts.G1DST = []byte(dstG1)
		opts.G2DST = []byte(dstG2)
	})
}

// aggregateSignatures aggregates the given signatures into a single signature.
// Returns compressed signature.
func aggregateSignatures(signatures []bls.Signature) (bls.Signature, error) {
	var g bls.G1
	return bls.Aggregate(g, signatures)
}

func generateAggregatedSigCBLS(msg []byte, sigN int) ([]*bls.PublicKey[bls.KeyG1SigG2], bls.Signature, error) {
	pks := make([]*bls.PublicKey[bls.G1], 0, sigN)
	sigs := make([]bls.Signature, 0, sigN)
	for i := range sigN {
		sk, err := generateSecretKey()
		if err != nil {
			return nil, bls.Signature{}, fmt.Errorf("failed to generate %d-th (%T): %w", i+1, sk, err)
		}
		sig := Sign(sk, msg)
		pks = append(pks, sk.PublicKey())
		sigs = append(sigs, sig)
	}
	aggregated, err := aggregateSignatures(sigs)
	if err != nil {
		return nil, bls.Signature{}, fmt.Errorf("failed to aggregate %d signatures: %w", sigN, err)
	}
	return pks, aggregated, nil
}

func SerializePkAndSigCBLS(pks []*bls.PublicKey[bls.KeyG1SigG2], sig bls.Signature) ([][]byte, []byte, error) {
	marshalledPk := make([][]byte, len(pks))
	for i, p := range pks {
		pk, err := p.MarshalBinary() // compressed
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal %d-th public key: %w", i+1, err)
		}
		marshalledPk[i] = pk
	}
	return marshalledPk, sig, nil
}

func unmarshalPK(marshalledPk []byte) (*bls.PublicKey[bls.KeyG1SigG2], error) {
	pk := new(bls.PublicKey[bls.KeyG1SigG2])
	if err := pk.UnmarshalBinary(marshalledPk); err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}
	if ok := pk.Validate(); !ok {
		return nil, fmt.Errorf("failed to validate public key")
	}
	return pk, nil
}

func unmarshalPKAndSigCBLS(
	marshalledPk [][]byte,
	sig []byte,
) ([]*bls.PublicKey[bls.KeyG1SigG2], bls.Signature, error) {
	// TODO: no validation of the signature
	pks := make([]*bls.PublicKey[bls.KeyG1SigG2], len(marshalledPk))
	for i, pkBytes := range marshalledPk {
		pk, err := unmarshalPK(pkBytes)
		if err != nil {
			return nil, bls.Signature{}, fmt.Errorf("failed to unmarshal %d-th public key: %w", i+1, err)
		}
		pks[i] = pk
	}
	return pks, sig, nil
}

func UnmarshalPkAndSigCBLSKeyG1SigG2(
	marshalledPk [][]byte,
	sig []byte,
) ([]*bls.PublicKey[bls.KeyG1SigG2], bls.Signature, error) {
	return unmarshalPKAndSigCBLS(marshalledPk, sig)
}

func GenerateAggregatedSigCBLSKeyG1SigG2(
	msg []byte,
	sigN int,
) ([]*bls.PublicKey[bls.KeyG1SigG2], bls.Signature, error) {
	pks, sig, err := generateAggregatedSigCBLS(msg, sigN)
	if err != nil {
		return nil, bls.Signature{}, fmt.Errorf("failed to generate aggregated signature: %w", err)
	}
	return pks, sig, nil
}

func VerifyAggregateCBLSKeyG1SigG2(pks []*bls.PublicKey[bls.KeyG1SigG2], msg []byte, aggSig bls.Signature) bool {
	msgs := make([][]byte, len(pks))
	for i := range len(pks) {
		msgs[i] = msg
	}
	return bls.VerifyAggregate(pks, msgs, aggSig, func(opts *bls.VerifyOpts) {
		opts.G1DST = []byte(dstG1)
		opts.G2DST = []byte(dstG2)
	})
}

func VerifyCBLSKeyG1SigG2(pk *bls.PublicKey[bls.KeyG1SigG2], msg []byte, sig bls.Signature) bool {
	return bls.Verify(pk, msg, sig, func(opts *bls.VerifyOpts) {
		opts.G1DST = []byte(dstG1)
		opts.G2DST = []byte(dstG2)
	})
}
