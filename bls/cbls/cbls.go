package cbls

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/bls"
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

func generateSecretKey[T bls.KeyGroup]() (*bls.PrivateKey[T], error) {
	b64 := read64RandomBytes()
	pk, err := bls.KeyGen[T](b64, []byte(salt32), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate (%T): %w", pk, err)
	}
	return pk, nil
}

func unmarshalSecretKey[T bls.KeyGroup](skBytes []byte) (*bls.PrivateKey[T], error) {
	sk := new(bls.PrivateKey[T])
	if err := sk.UnmarshalBinary(skBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret key: %w", err)
	}
	if ok := sk.Validate(); !ok {
		return nil, fmt.Errorf("failed to validate secret key")
	}
	return sk, nil
}

func UnmarshalSecretKeyG1SigG2(skBytes []byte) (*bls.PrivateKey[bls.KeyG1SigG2], error) {
	sk, err := unmarshalSecretKey[bls.G1](skBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret key: %w", err)
	}
	return sk, nil
}

// sign signs the message with the given private key. Returns compressed signature.
func sign[T bls.KeyGroup](pk *bls.PrivateKey[T], msg []byte) bls.Signature { return bls.Sign(pk, msg) }

// aggregateSignatures aggregates the given signatures into a single signature.
// Returns compressed signature.
func aggregateSignatures[T bls.KeyGroup](signatures []bls.Signature) (bls.Signature, error) {
	var g T
	return bls.Aggregate(g, signatures)
}

func generateAggregatedSigCBLS[T bls.KeyGroup](msg []byte, sigN int) ([]*bls.PublicKey[T], bls.Signature, error) {
	pks := make([]*bls.PublicKey[T], 0, sigN)
	sigs := make([]bls.Signature, 0, sigN)
	for i := range sigN {
		sk, err := generateSecretKey[T]()
		if err != nil {
			return nil, bls.Signature{}, fmt.Errorf("failed to generate %d-th (%T): %w", i+1, sk, err)
		}
		sig := sign(sk, msg)
		pks = append(pks, sk.PublicKey())
		sigs = append(sigs, sig)
	}
	aggregated, err := aggregateSignatures[T](sigs)
	if err != nil {
		return nil, bls.Signature{}, fmt.Errorf("failed to aggregate %d signatures: %w", sigN, err)
	}
	return pks, aggregated, nil
}

func SerializePkAndSigCBLS[T bls.KeyGroup](pks []*bls.PublicKey[T], sig bls.Signature) ([][]byte, []byte, error) {
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

func unmarshalPK[T bls.KeyGroup](marshalledPk []byte) (*bls.PublicKey[T], error) {
	pk := new(bls.PublicKey[T])
	if err := pk.UnmarshalBinary(marshalledPk); err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}
	if ok := pk.Validate(); !ok {
		return nil, fmt.Errorf("failed to validate public key")
	}
	return pk, nil
}

func unmarshalPKAndSigCBLS[T bls.KeyGroup](
	marshalledPk [][]byte,
	sig []byte,
) ([]*bls.PublicKey[T], bls.Signature, error) {
	// TODO: no validation of the signature
	pks := make([]*bls.PublicKey[T], len(marshalledPk))
	for i, pkBytes := range marshalledPk {
		pk, err := unmarshalPK[T](pkBytes)
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
	return unmarshalPKAndSigCBLS[bls.G1](marshalledPk, sig)
}

func GenerateAggregatedSigCBLSKeyG1SigG2(
	msg []byte,
	sigN int,
) ([]*bls.PublicKey[bls.KeyG1SigG2], bls.Signature, error) {
	pks, sig, err := generateAggregatedSigCBLS[bls.G1](msg, sigN)
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
	return bls.VerifyAggregate(pks, msgs, aggSig)
}
