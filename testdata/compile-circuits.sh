#!/bin/sh

npm install

powers_of_tau_phase1() {
  echo $(date +"%T") "powers of tau phase1"
  itime="$(date -u +%s)"
  echo "new powers of tau"
  ./node_modules/.bin/snarkjs powersoftau new bn128 12 pot12_0000.ptau -v
  echo "second contribution"
  ./node_modules/.bin/snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First contribution" -v -e=test
  echo "apply random beacon"
  ./node_modules/.bin/snarkjs powersoftau beacon pot12_0001.ptau pot12_beacon.ptau 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon"
  echo "prepare phase 2"
  ./node_modules/.bin/snarkjs powersoftau prepare phase2 pot12_beacon.ptau pot12_final.ptau -v

  ./node_modules/.bin/snarkjs powersoftau verify pot12_final.ptau

  ftime="$(date -u +%s)"
  echo "	($(($(date -u +%s)-$itime))s)"
}

compile_and_ts_and_witness() {
  echo $(date +"%T") "circom circuit.circom --r1cs --wasm --sym -v"
  itime="$(date -u +%s)"
  ../node_modules/.bin/circom circuit.circom --r1cs --wasm --sym -v
  ftime="$(date -u +%s)"
  echo "	($(($(date -u +%s)-$itime))s)"

  echo $(date +"%T") "snarkjs r1cs info circuit.r1cs"
  ../node_modules/.bin/snarkjs r1cs info circuit.r1cs

  echo $(date +"%T") "snarkjs groth16 setup circuit.r1cs ../pot12_final.ptau circuit_0000.zkey"
  itime="$(date -u +%s)"
  ../node_modules/.bin/snarkjs groth16 setup circuit.r1cs ../pot12_final.ptau circuit_0000.zkey
  ../node_modules/.bin/snarkjs zkey contribute circuit_0000.zkey circuit_0001.zkey --name="1st Contributor Name" -v -e=test
  ../node_modules/.bin/snarkjs zkey verify circuit.r1cs ../pot12_final.ptau circuit_0001.zkey
  ../node_modules/.bin/snarkjs zkey beacon circuit_0001.zkey circuit_final.zkey 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon phase2"
  ../node_modules/.bin/snarkjs zkey verify circuit.r1cs ../pot12_final.ptau circuit_final.zkey
  ../node_modules/.bin/snarkjs zkey export json circuit_final.zkey circuit_final.json
  echo "	($(($(date -u +%s)-$itime))s)"
  echo $(date +"%T") "trusted setup generated"

  echo "export verification key"
  ../node_modules/.bin/snarkjs zkey export verificationkey circuit_final.zkey verification_key.json

  # sed -i 's/null/["0","0","0"]/g' proving_key.json

  echo "calculating witness"
  ../node_modules/.bin/snarkjs wtns calculate circuit.wasm inputs.json witness.wtns
  ../node_modules/.bin/snarkjs wtns export json witness.wtns witness.json

  echo $(date +"%T") "snarkjs generateverifier"
  itime="$(date -u +%s)"
  ../node_modules/.bin/snarkjs zkey export solidityverifier circuit_final.zkey verifier.sol
  echo "	($(($(date -u +%s)-$itime))s)"
  echo $(date +"%T") "generateverifier generated"
}

powers_of_tau_phase1

echo "compile & trustesetup for circuit1k"
cd circuit1k
compile_and_ts_and_witness
# echo "compile & trustesetup for circuit5k"
# cd ../circuit5k
# compile_and_ts_and_witness
# echo "compile & trustesetup for circuit10k"
# cd ../circuit10k
# compile_and_ts_and_witness
# echo "compile & trustesetup for circuit20k"
# cd ../circuit20k
# compile_and_ts_and_witness

cd ../

echo "convert witness & pk of circuit1k to bin & go bin"
# node node_modules/wasmsnark/tools/buildwitness.js -i circuit1k/witness.json -o circuit1k/witness.bin
# node node_modules/wasmsnark/tools/buildpkey.js -i circuit1k/proving_key.json -o circuit1k/proving_key.bin
# sed -i 's/alfa/alpha/g' circuit1k/verification_key.json # after wasmsnark finished using proving_key.bin
# sed -i 's/alfa/alpha/g' circuit1k/proving_key.json # after wasmsnark finished using proving_key.bin
# go run ../cli/cli.go -convert -pk circuit1k/proving_key.json -pkbin circuit1k/proving_key.go.bin

# echo "convert witness & pk of circuit5k to bin & go bin"
# node node_modules/wasmsnark/tools/buildwitness.js -i circuit5k/witness.json -o circuit5k/witness.bin
# node node_modules/wasmsnark/tools/buildpkey.js -i circuit5k/proving_key.json -o circuit5k/proving_key.bin
# sed -i 's/alfa/alpha/g' circuit5k/verification_key.json # after wasmsnark finished using proving_key.bin
# sed -i 's/alfa/alpha/g' circuit5k/proving_key.json # after wasmsnark finished using proving_key.bin
# go run ../cli/cli.go -convert -pk circuit5k/proving_key.json -pkbin circuit5k/proving_key.go.bin

# echo "convert witness & pk of circuit10k to bin & go bin"
# node node_modules/wasmsnark/tools/buildwitness.js -i circuit10k/witness.json -o circuit10k/witness.bin
# node node_modules/wasmsnark/tools/buildpkey.js -i circuit10k/proving_key.json -o circuit10k/proving_key.bin
# sed -i 's/alfa/alpha/g' circuit10k/verification_key.json # after wasmsnark finished using proving_key.bin
# sed -i 's/alfa/alpha/g' circuit10k/proving_key.json # after wasmsnark finished using proving_key.bin
# go run ../cli/cli.go -convert -pk circuit10k/proving_key.json -pkbin circuit10k/proving_key.go.bin
# 
# echo "convert witness & pk of circuit20k to bin & go bin"
# node node_modules/wasmsnark/tools/buildwitness.js -i circuit20k/witness.json -o circuit20k/witness.bin
# node node_modules/wasmsnark/tools/buildpkey.js -i circuit20k/proving_key.json -o circuit20k/proving_key.bin
# sed -i 's/alfa/alpha/g' circuit20k/verification_key.json # after wasmsnark finished using proving_key.bin
# sed -i 's/alfa/alpha/g' circuit20k/proving_key.json # after wasmsnark finished using proving_key.bin
# go run ../cli/cli.go -convert -pk circuit20k/proving_key.json -pkbin circuit20k/proving_key.go.bin

