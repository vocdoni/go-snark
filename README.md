# go-snark [![GoDoc](https://godoc.org/github.com/vocdoni/go-snark?status.svg)](https://godoc.org/github.com/vocdoni/go-snark) [![Go Report Card](https://goreportcard.com/badge/github.com/vocdoni/go-snark)](https://goreportcard.com/report/github.com/vocdoni/go-snark) [![Test](https://github.com/vocdoni/go-snark/workflows/Test/badge.svg)](https://github.com/vocdoni/go-snark/actions?query=workflow%3ATest)

Go implementation of the [Groth16 protocol](https://eprint.iacr.org/2016/260.pdf) zkSNARK prover & verifier compatible with:

- [circom](https://github.com/iden3/circom) (WIP)
- [bellman](https://github.com/zkcrypto/bellman) (TODO)


Using [bn256](https://github.com/ethereum/go-ethereum/tree/master/crypto/bn256/cloudflare) (used by [go-ethereum](https://github.com/ethereum/go-ethereum)) for the Pairing curve operations.

### Usage

- Generate Proof

```go
import (
  "github.com/vocdoni/go-snark/parsers"
  "github.com/vocdoni/go-snark/prover"
  "github.com/vocdoni/go-snark/verifier"
)

[...]

// read ProvingKey & Witness files
provingKeyJSON, _ := ioutil.ReadFile("../testdata/circuit1k/proving_key.json")
witnessJSON, _ := ioutil.ReadFile("../testdata/circuit1k/witness.json")

// parse Proving Key
pk, _ := parsers.ParsePk(provingKeyJSON)

// parse Witness
w, _ := parsers.ParseWitness(witnessJSON)

// generate the proof
proof, pubSignals, _ := prover.GenerateProof(pk, w)

// print proof & publicSignals
proofStr, _ := parsers.ProofToJSON(proof)
publicStr, _ := json.Marshal(parsers.ArrayBigIntToString(pubSignals))
fmt.Println(proofStr)
fmt.Println(publicStr)
```

- Verify Proof

```go
// read proof & verificationKey & publicSignals
proofJSON, _ := ioutil.ReadFile("../testdata/circuit1k/proof.json")
vkJSON, _ := ioutil.ReadFile("../testdata/circuit1k/verification_key.json")
publicJSON, _ := ioutil.ReadFile("../testdata/circuit1k/public.json")

// parse proof & verificationKey & publicSignals
public, _ := parsers.ParsePublicSignals(publicJSON)
proof, _ := parsers.ParseProof(proofJSON)
vk, _ := parsers.ParseVk(vkJSON)

// verify the proof with the given verificationKey & publicSignals
v := verifier.Verify(vk, proof, public)
fmt.Println(v)
```

### CLI

From the `cli` directory:

- Show options

```
> go run cli.go -help
go-snark
                 v0.0.1
Usage of go-snark:
  -proof string
        proof path (default "proof.json")
  -prove
        prover mode
  -provingkey string
        provingKey path (default "proving_key.json")
  -public string
        public signals path (default "public.json")
  -verificationkey string
        verificationKey path (default "verification_key.json")
  -verify
        verifier mode
  -witness string
        witness path (default "witness.json")
```

- Prove

```
> go run cli.go -prove -provingkey=../testdata/circuit5k/proving_key.json -witness=../testdata/circuit5k/witness.json
```

- Verify

```
> go run cli.go -verify -verificationkey=../testdata/circuit5k/verification_key.json
```
