package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/vocdoni/go-snark/parsers"
	"github.com/vocdoni/go-snark/prover"
	"github.com/vocdoni/go-snark/verifier"
)

const version = "v0.0.1"

func main() {
	fmt.Println("go-snark")
	fmt.Println("		", version)

	prove := flag.Bool("prove", false, "prover mode")
	verify := flag.Bool("verify", false, "verifier mode")
	convert := flag.Bool("convert", false, "convert mode, to convert between"+
		" proving_key.json to proving_key.go.bin")

	provingKeyPath := flag.String("pk", "proving_key.json", "provingKey path")
	witnessPath := flag.String("witness", "witness.json", "witness path")
	proofPath := flag.String("proof", "proof.json", "proof path")
	verificationKeyPath := flag.String("vk", "verification_key.json", "verificationKey path")
	publicPath := flag.String("public", "public.json", "public signals path")
	provingKeyBinPath := flag.String("pkbin", "proving_key.go.bin", "provingKey Bin path")

	flag.Parse()

	if *prove {
		err := cmdProve(*provingKeyPath, *witnessPath, *proofPath, *publicPath)
		if err != nil {
			fmt.Println("Error:", err)
		}
		os.Exit(0)
	} else if *verify {
		err := cmdVerify(*proofPath, *verificationKeyPath, *publicPath)
		if err != nil {
			fmt.Println("Error:", err)
		}
		os.Exit(0)
	} else if *convert {
		err := cmdConvert(*provingKeyPath, *provingKeyBinPath)
		if err != nil {
			fmt.Println("Error:", err)
		}
		os.Exit(0)
	}
	flag.PrintDefaults()
}

func cmdProve(provingKeyPath, witnessPath, proofPath, publicPath string) error {
	fmt.Println("zkSNARK Groth16 prover")

	fmt.Println("Reading proving key file:", provingKeyPath)
	provingKeyJSON, err := ioutil.ReadFile(provingKeyPath) //nolint:gosec
	if err != nil {
		return err
	}
	pk, err := parsers.ParsePk(provingKeyJSON)
	if err != nil {
		return err
	}

	fmt.Println("Reading witness file:", witnessPath)
	witnessJSON, err := ioutil.ReadFile(witnessPath) //nolint:gosec
	if err != nil {
		return err
	}
	w, err := parsers.ParseWitness(witnessJSON)
	if err != nil {
		return err
	}

	fmt.Println("Generating the proof")
	beforeT := time.Now()
	proof, pubSignals, err := prover.GenerateProof(pk, w)
	if err != nil {
		return err
	}
	fmt.Println("proof generation time elapsed:", time.Since(beforeT))

	proofStr, err := parsers.ProofToJSON(proof)
	if err != nil {
		return err
	}

	// write output
	err = ioutil.WriteFile(proofPath, proofStr, 0600)
	if err != nil {
		return err
	}
	publicStr, err := json.Marshal(parsers.ArrayBigIntToString(pubSignals))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(publicPath, publicStr, 0600)
	if err != nil {
		return err
	}
	fmt.Println("Proof stored at:", proofPath)
	fmt.Println("PublicSignals stored at:", publicPath)
	return nil
}

func cmdVerify(proofPath, verificationKeyPath, publicPath string) error {
	fmt.Println("zkSNARK Groth16 verifier")

	proofJSON, err := ioutil.ReadFile(proofPath) //nolint:gosec
	if err != nil {
		return err
	}
	vkJSON, err := ioutil.ReadFile(verificationKeyPath) //nolint:gosec
	if err != nil {
		return err
	}
	publicJSON, err := ioutil.ReadFile(publicPath) //nolint:gosec
	if err != nil {
		return err
	}

	public, err := parsers.ParsePublicSignals(publicJSON)
	if err != nil {
		return err
	}
	proof, err := parsers.ParseProof(proofJSON)
	if err != nil {
		return err
	}
	vk, err := parsers.ParseVk(vkJSON)
	if err != nil {
		return err
	}

	v := verifier.Verify(vk, proof, public)
	fmt.Println("verification:", v)
	return nil
}

func cmdConvert(provingKeyPath, provingKeyBinPath string) error {
	fmt.Println("Conversion tool")

	provingKeyJSON, err := ioutil.ReadFile(provingKeyPath) //nolint:gosec
	if err != nil {
		return err
	}
	pk, err := parsers.ParsePk(provingKeyJSON)
	if err != nil {
		return err
	}

	fmt.Printf("Converting proving key json (%s)\nto go proving key binary (%s)\n",
		provingKeyPath, provingKeyBinPath)
	pkGBin, err := parsers.PkToGoBin(pk)
	if err != nil {
		return err
	}
	if err = ioutil.WriteFile(provingKeyBinPath, pkGBin, 0600); err != nil {
		return err
	}

	return nil
}
