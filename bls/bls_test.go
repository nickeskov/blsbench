package bls_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"blsbench/bls/cbls"
	"blsbench/bls/pbls"
)

func TestCBLSGenPBLSVerify(t *testing.T) {
	const (
		sigN = 10
	)
	var message = [42]byte{'c', 'b', 'l', 's', ' ', 't', 'e', 's', 't'}
	cblsPKs, cblsAggSig, err := cbls.GenerateAggregatedSigCBLSKeyG1SigG2(message[:], sigN)
	require.NoError(t, err)
	cblsMPKs, cblsMAggSig, err := cbls.SerializePkAndSigCBLS(cblsPKs, cblsAggSig)
	require.NoError(t, err)

	// unmarshal the cbls keys and signature to pbls format
	pblsPKs, pblsAggSig, err := pbls.UnmarshalPkAndSigPrysmBLS(cblsMPKs, cblsMAggSig)
	require.NoError(t, err)

	// aggregate the public keys
	pblsAggPk := pbls.AggregatePublicKeysPrysmBLS(pblsPKs)
	// Verify the aggregated signature
	isValid := pblsAggSig.Verify(pblsAggPk, message[:])
	require.True(t, isValid, "aggregated signature verification failed")
}

func TestPBLSToCBLSVerify(t *testing.T) {
	const (
		sigN = 10
	)
	var message = [32]byte{'p', 'b', 'l', 's', ' ', 't', 'e', 's', 't'}
	pblsPKs, pblsAggSig, err := pbls.GenerateAggregatedSigPrysmBLS(message[:], sigN)
	require.NoError(t, err)
	pblsMPKs, pblsMAggSig := pbls.SerializePkAndSigPrysmBLS(pblsPKs, pblsAggSig)

	// unmarshal the pbls keys and signature to cbls format
	cblsPKs, cblsAggSig, err := cbls.UnmarshalPkAndSigCBLSKeyG1SigG2(pblsMPKs, pblsMAggSig)
	require.NoError(t, err)

	// aggregate the public keys
	cblsAggPk := cbls.VerifyAggregateCBLSKeyG1SigG2(cblsPKs, message[:], cblsAggSig)
	require.True(t, cblsAggPk, "aggregated signature verification failed")
}

func TestCBLStoCBLSVerify(t *testing.T) {
	const (
		sigN = 10
	)
	var message = [32]byte{'c', 'b', 'l', 's', ' ', 't', 'e', 's', 't'}
	cblsPKs, cblsAggSig, err := cbls.GenerateAggregatedSigCBLSKeyG1SigG2(message[:], sigN)
	require.NoError(t, err)
	cblsMPKs, cblsMAggSig, err := cbls.SerializePkAndSigCBLS(cblsPKs, cblsAggSig)
	require.NoError(t, err)

	// unmarshal the cbls keys and signature to cbls format
	cblsPKs2, cblsAggSig2, err := cbls.UnmarshalPkAndSigCBLSKeyG1SigG2(cblsMPKs, cblsMAggSig)
	require.NoError(t, err)

	// aggregate the public keys
	cblsAggPk := cbls.VerifyAggregateCBLSKeyG1SigG2(cblsPKs2, message[:], cblsAggSig2)
	require.True(t, cblsAggPk, "aggregated signature verification failed")
}

func TestPBLSToPBLSVerify(t *testing.T) {
	const (
		sigN = 10
	)
	var message = [32]byte{'p', 'b', 'l', 's', ' ', 't', 'e', 's', 't'}
	pblsPKs, pblsAggSig, err := pbls.GenerateAggregatedSigPrysmBLS(message[:], sigN)
	require.NoError(t, err)
	pblsMPKs, pblsMAggSig := pbls.SerializePkAndSigPrysmBLS(pblsPKs, pblsAggSig)

	// unmarshal the pbls keys and signature to pbls format
	pblsPKs2, pblsAggSig2, err := pbls.UnmarshalPkAndSigPrysmBLS(pblsMPKs, pblsMAggSig)
	require.NoError(t, err)

	// aggregate the public keys
	pblsAggPk := pbls.AggregatePublicKeysPrysmBLS(pblsPKs2)
	// Verify the aggregated signature
	isValid := pblsAggSig2.Verify(pblsAggPk, message[:])
	require.True(t, isValid, "aggregated signature verification failed")
}

func TestPBLSPKSameCBLSPK(t *testing.T) {
	pblsSK, err := pbls.RandKeyPrysmBLS()
	require.NoError(t, err)
	pblsPK := pblsSK.PublicKey()
	pblsMPK := pblsPK.Marshal()

	msk := pblsSK.Marshal()

	cblsSK, err := cbls.UnmarshalSecretKeyG1SigG2(msk)
	require.NoError(t, err)
	cblsPK := cblsSK.PublicKey()
	cblsMPK, err := cblsPK.MarshalBinary()
	require.NoError(t, err)

	assert.Equal(t, pblsMPK, cblsMPK)
}
