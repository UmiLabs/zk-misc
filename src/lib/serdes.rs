pub use ark_bn254::{Bn254 as Curve, Fr};
use ark_serialize::CanonicalSerialize;
use num_bigint::BigInt;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::serde_as;
use std::{collections::HashMap, fs};

pub fn load_public_inputs_from_file(file_path: &str) -> HashMap<String, Vec<BigInt>> {
    let data = fs::read_to_string(file_path).expect("Unable to read file");
    let inputs: Value = serde_json::from_str(&data).expect("JSON was not well-formatted");
    let mut map = HashMap::new();

    if let Value::Object(entries) = inputs {
        for (key, value) in entries {
            if let Value::String(s) = value {
                map.insert(
                    key,
                    vec![BigInt::from_str_radix(&s, 10).expect("Failed to parse BigInt")],
                );
            }
        }
    }

    map
}

pub fn to_bytes<T: CanonicalSerialize>(data: &T) -> Vec<u8> {
    let mut bytes = vec![];
    data.serialize_compressed(&mut bytes).unwrap();
    bytes
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputs<Fr> {
    pub public_inputs: Vec<Fr>,
}

impl PublicInputs<Fr> {
    pub fn new(public_inputs: Vec<Fr>) -> Self {
        Self { public_inputs }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];
        for data in &self.public_inputs {
            data.serialize_compressed(&mut buffer).unwrap();
        }
        buffer
    }
}
