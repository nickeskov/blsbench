package pbls

import (
	"fmt"

	"github.com/prysmaticlabs/prysm/v5/crypto/bls/blst"
	"github.com/prysmaticlabs/prysm/v5/crypto/bls/common"
)

func GenerateAggregatedSigPrysmBLS(msg []byte, sigN int) ([]common.PublicKey, common.Signature, error) {
	var pks []common.PublicKey
	var sigs []common.Signature
	for i := range sigN {
		sk, err := RandKeyPrysmBLS()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate %d-th key: %w", i+1, err)
		}
		sig := sk.Sign(msg)
		pks = append(pks, sk.PublicKey())
		sigs = append(sigs, sig)
	}
	aggregatedSig := blst.AggregateSignatures(sigs)
	return pks, aggregatedSig, nil
}

func RandKeyPrysmBLS() (common.SecretKey, error) {
	sk, err := blst.RandKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return sk, nil
}

func SerializePkAndSigPrysmBLS(pk []common.PublicKey, sig common.Signature) ([][]byte, []byte) {
	marshalledPk := make([][]byte, len(pk))
	for i, p := range pk {
		marshalledPk[i] = p.Marshal()
	}
	sigBytes := sig.Marshal()
	return marshalledPk, sigBytes
}

func AggregatePublicKeysPrysmBLS(pks []common.PublicKey) common.PublicKey {
	return blst.AggregateMultiplePubkeys(pks)
}

func UnmarshalPkAndSigPrysmBLS(marshalledPk [][]byte, sigBytes []byte) ([]common.PublicKey, common.Signature, error) {
	sig, sErr := blst.SignatureFromBytes(sigBytes)
	if sErr != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal signature: %w", sErr)
	}
	pks := make([]common.PublicKey, len(marshalledPk))
	for i, pkBytes := range marshalledPk {
		pk, err := blst.PublicKeyFromBytes(pkBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal %d-th public key: %w", i+1, err)
		}
		pks[i] = pk
	}
	return pks, sig, nil
}
