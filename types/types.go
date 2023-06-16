package types

import (
	"encoding/hex"
	"encoding/json"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
)

// Q is the order of the integer field (Zq) that fits inside the snark
var Q, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

// R is the mod of the finite field
var R, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// Proof is the data structure of the Groth16 zkSNARK proof
type Proof struct {
	A *curve.G1Affine
	B *curve.G2Affine
	C *curve.G1Affine
}

type proofAux struct {
	A string `json:"pi_a"`
	B string `json:"pi_b"`
	C string `json:"pi_c"`
}

// MarshalJSON implements the JSON marshaler for Proof type
func (p Proof) MarshalJSON() ([]byte, error) {
	var pa proofAux
	pa.A = hex.EncodeToString(p.A.Marshal())
	pa.B = hex.EncodeToString(p.B.Marshal())
	pa.C = hex.EncodeToString(p.C.Marshal())
	return json.Marshal(pa)
}

// UnmarshalJSON implements the JSON unmarshaler for Proof type
func (p *Proof) UnmarshalJSON(data []byte) error {
	var pa proofAux
	if err := json.Unmarshal(data, &pa); err != nil {
		return err
	}
	aBytes, err := hex.DecodeString(pa.A)
	if err != nil {
		return err
	}
	p.A = new(curve.G1Affine)
	if err := p.A.Unmarshal(aBytes); err != nil {
		return err
	}
	bBytes, err := hex.DecodeString(pa.B)
	if err != nil {
		return err
	}
	p.B = new(curve.G2Affine)
	if err := p.B.Unmarshal(bBytes); err != nil {
		return err
	}
	cBytes, err := hex.DecodeString(pa.C)
	if err != nil {
		return err
	}
	p.C = new(curve.G1Affine)
	if err := p.C.Unmarshal(cBytes); err != nil {
		return err
	}
	return nil
}

// Pk holds the data structure of the ProvingKey
type Pk struct {
	A          []*curve.G1Affine
	B2         []*curve.G2Affine
	B1         []*curve.G1Affine
	C          []*curve.G1Affine
	NVars      int
	NPublic    int
	VkAlpha1   *curve.G1Affine
	VkDelta1   *curve.G1Affine
	VkBeta1    *curve.G1Affine
	VkBeta2    *curve.G2Affine
	VkDelta2   *curve.G2Affine
	HExps      []*curve.G1Affine
	DomainSize int
	PolsA      []map[int]*big.Int
	PolsB      []map[int]*big.Int
}

// Witness contains the witness
type Witness []*big.Int

// Vk is the Verification Key data structure
type Vk struct {
	Alpha *curve.G1Affine
	Beta  *curve.G2Affine
	Gamma *curve.G2Affine
	Delta *curve.G2Affine
	IC    []*curve.G1Affine
}
