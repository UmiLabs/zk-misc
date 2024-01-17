pub use ark_bn254::{Bn254 as Curve, Fr};
use ark_serialize::{CanonicalDeserialize, Write};
use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};
use std::{fs::File, path::Path};

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Groth16Verifier {
    #[serde_as(as = "Hex")]
    pub vk: Vec<u8>,
    #[serde_as(as = "Hex")]
    pub public_inputs: Vec<u8>,
    #[serde_as(as = "Hex")]
    pub proof: Vec<u8>,
}

impl Groth16Verifier {
    pub fn new(vk: &[u8], public_inputs: &[u8], proof: &[u8]) -> Self {
        Self {
            vk: vk.to_vec(),
            public_inputs: public_inputs.to_vec(),
            proof: proof.to_vec(),
        }
    }

    pub fn print_info(&self) {
        println!("vk size: {}", self.vk.len());
        println!("proof size: {}", self.proof.len());
    }

    pub fn dump_json(&self, path: &Path) {
        let serialized_data = serde_json::to_string(&self).expect("");
        let mut file = File::create(path).expect("");
        file.write_all(serialized_data.as_bytes()).expect("");
    }

    pub fn verify(&self) -> bool {
        let vk = ark_groth16::VerifyingKey::<Curve>::deserialize_compressed(&self.vk[..]).unwrap();
        let vk_wrapped = fastcrypto_zkp::bn254::VerifyingKey::from(vk);
        let pvk = fastcrypto_zkp::bn254::verifier::process_vk_special(&vk_wrapped);
        let result =
            fastcrypto_zkp::bn254::api::verify_groth16(&pvk, &self.public_inputs, &self.proof)
                .expect("failed to verify");
        result
    }
}
