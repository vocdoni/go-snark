package verifier

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vocdoni/go-snark/parsers"
)

func TestVerify(t *testing.T) {
	testVerifyCircuit(t, "circuit1k")
	testVerifyCircuit(t, "circuit5k")
	// testVerifyCircuit(t, "circuit10k")
	// testVerifyCircuit(t, "circuit20k")
}

func testVerifyCircuit(t *testing.T, circuit string) {
	proofJSON, err := ioutil.ReadFile("../testdata/" + circuit + "/proof.json") //nolint:gosec
	require.Nil(t, err)
	vkJSON, err := ioutil.ReadFile("../testdata/" + circuit + "/verification_key.json") //nolint:gosec
	require.Nil(t, err)
	publicJSON, err := ioutil.ReadFile("../testdata/" + circuit + "/public.json") //nolint:gosec
	require.Nil(t, err)

	public, err := parsers.ParsePublicSignals(publicJSON)
	require.Nil(t, err)
	proof, err := parsers.ParseProof(proofJSON)
	require.Nil(t, err)
	vk, err := parsers.ParseVk(vkJSON)
	require.Nil(t, err)

	v := Verify(vk, proof, public)
	assert.True(t, v)

	// Verify again to check that `Verify` hasn't mutated the inputs
	v = Verify(vk, proof, public)
	assert.True(t, v)
}

func BenchmarkVerify(b *testing.B) {
	// benchmark with circuit2 (10000 constraints)
	proofJSON, err := ioutil.ReadFile("../testdata/circuit2/proof.json")
	require.Nil(b, err)
	vkJSON, err := ioutil.ReadFile("../testdata/circuit2/verification_key.json")
	require.Nil(b, err)
	publicJSON, err := ioutil.ReadFile("../testdata/circuit2/public.json")
	require.Nil(b, err)

	public, err := parsers.ParsePublicSignals(publicJSON)
	require.Nil(b, err)
	proof, err := parsers.ParseProof(proofJSON)
	require.Nil(b, err)
	vk, err := parsers.ParseVk(vkJSON)
	require.Nil(b, err)

	for i := 0; i < b.N; i++ {
		Verify(vk, proof, public)
	}
}
