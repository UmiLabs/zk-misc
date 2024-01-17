install-circom:
    cargo install --git https://github.com/iden3/circom.git

run-examples:
    cargo run -r --example mul
    cargo run -r --example sha256

    @just build-circom mul
    cargo run -r --example circom

    @just e2e mul

e2e ARG="mul":
    cargo run -r -- --wasm output/{{ARG}}_js/{{ARG}}.wasm --r1cs output/{{ARG}}.r1cs --inputs circuits/{{ARG}}-inputs.json


build-circom ARG="entry":
    circom circuits/{{ARG}}.circom --r1cs --wasm --sym -o output

dev-circom ARG="entry":
    circom circuits/{{ARG}}.circom --r1cs --wasm -o output

info-circom ARG="entry":
    bunx snarkjs r1cs info output/{{ARG}}.r1cs
    bunx snarkjs r1cs print output/{{ARG}}.r1cs output/{{ARG}}.sym

r1cs-export-json:
    bunx snarkjs r1cs export json output/jolt_single_step.r1cs circuit.r1cs.json
