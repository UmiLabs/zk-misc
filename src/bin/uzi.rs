pub use ark_bn254::{Bn254 as Curve, Fr};
use ark_circom::{CircomBuilder, CircomConfig};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_std::rand::thread_rng;
use ark_utils::serdes::PublicInputs;
use clap::Parser;
use serde_json::Value;
use std::fs;

/// Usage:
///     uzi --wasm output/mul_js/mul.wasm --r1cs output/mul.r1cs --inputs circuits/mul-inputs.json
#[derive(Parser, Debug)]
struct Args {
    /// Witness file
    #[clap(long = "wasm")]
    wasm_file: std::path::PathBuf,

    /// Constraint file
    #[clap(long = "r1cs")]
    r1cs_file: std::path::PathBuf,

    /// Inputs JSON file
    #[clap(long = "inputs")]
    inputs: std::path::PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let inputs = read_json_inputs(&args.inputs).expect("Failed to read inputs file");

    routine(
        &args.wasm_file.display().to_string(),
        &args.r1cs_file.display().to_string(),
        &inputs,
    );

    Ok(())
}

fn read_json_inputs(
    file_path: &std::path::PathBuf,
) -> Result<Vec<(String, i64)>, Box<dyn std::error::Error>> {
    let file_contents = fs::read_to_string(file_path)?;
    let json: Value = serde_json::from_str(&file_contents)?;

    let mut inputs = Vec::new();
    if let Some(obj) = json.as_object() {
        for (key, value) in obj {
            if let Some(value) = value.as_i64() {
                inputs.push((key.clone(), value));
            }
        }
    }

    Ok(inputs)
}

fn routine(witness_file: &str, constrains_file: &str, inputs: &[(String, i64)]) {
    type GrothSetup = Groth16<Curve>;
    let mut rng = thread_rng();

    let cfg = CircomConfig::<Curve>::new(witness_file, constrains_file).unwrap();
    let mut builder = CircomBuilder::new(cfg);
    for (name, value) in inputs.iter() {
        builder.push_input(name, *value);
    }

    let circom = builder.setup();
    let pk =
        GrothSetup::generate_random_parameters_with_reduction(circom.clone(), &mut rng).unwrap();
    let circuit = builder.build().unwrap();

    let public_inputs = circuit.get_public_inputs().unwrap();

    let proof = GrothSetup::prove(&pk, circuit, &mut rng).unwrap();
    let res = GrothSetup::verify(&pk.vk, &public_inputs, &proof).unwrap();
    assert!(res);
    println!("Proof verified: {}", res);

    {
        let public_inputs = PublicInputs::new(public_inputs);

        let start = ark_std::time::Instant::now();
        let vk = fastcrypto_zkp::bn254::VerifyingKey::from(pk.vk);
        let pvk = fastcrypto_zkp::bn254::verifier::process_vk_special(&vk);
        let public_inputs_bytes = public_inputs.to_bytes();

        let result = fastcrypto_zkp::bn254::api::verify_groth16(
            &pvk,
            &public_inputs_bytes.clone(),
            &ark_utils::serdes::to_bytes(&proof),
        )
        .expect("failed to verify");
        assert!(result);
        println!("verifying time: {} ms", start.elapsed().as_millis());
    }
}
