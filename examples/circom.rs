pub use ark_bn254::{Bn254 as Curve, Fr};
use ark_circom::{CircomBuilder, CircomConfig};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_std::rand::thread_rng;

fn main() {
    type GrothSetup = Groth16<Curve>;
    let mut rng = thread_rng();
    let witness_file = "output/mul_js/mul.wasm";
    let constrains_file = "output/mul.r1cs";
    let inputs = [("a", 3), ("b", 5), ("expected", 15)];

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
}
