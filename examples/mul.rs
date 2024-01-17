use ark_bn254::{Bn254 as Curve, Fr};
use ark_ff::Field;
use ark_ff::{PrimeField, ToConstraintField};
use ark_groth16::Groth16;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::UniformRand;
use rand::thread_rng;
use std::clone::Clone;
use std::ops::Mul;

#[derive(Copy, Clone)]
struct MultiplyDemoCircuit<F: Field> {
    input_a: Option<F>,
    input_b: Option<F>,
    expected: Option<F>,
}

impl<F: Field> MultiplyDemoCircuit<F> {
    pub fn new(input_a: F, input_b: F, expected: F) -> Self {
        Self {
            input_a: Some(input_a),
            input_b: Some(input_b),
            expected: Some(expected),
        }
    }
}

impl<ConstraintF: PrimeField> ConstraintSynthesizer<ConstraintF>
    for MultiplyDemoCircuit<ConstraintF>
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let a = FpVar::new_variable(
            cs.clone(),
            || self.input_a.ok_or(SynthesisError::AssignmentMissing),
            AllocationMode::Witness,
        )?;

        let b = FpVar::new_variable(
            cs.clone(),
            || self.input_b.ok_or(SynthesisError::AssignmentMissing),
            AllocationMode::Witness,
        )?;

        let expected = FpVar::new_variable(
            cs,
            || self.expected.ok_or(SynthesisError::AssignmentMissing),
            AllocationMode::Input,
        )?;

        let actual = a.mul(b);
        expected.enforce_equal(&actual)?;

        Ok(())
    }
}

fn main() {
    type GrothSetup = Groth16<Curve>;
    let mut rng = thread_rng();

    let a = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);
    let expected = a.mul(b);

    let circuit = MultiplyDemoCircuit::new(a, b, expected);
    let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
    let proof = GrothSetup::prove(&pk, circuit, &mut rng).unwrap();
    let res = GrothSetup::verify(&vk, &expected.to_field_elements().unwrap(), &proof).unwrap();
    assert!(res);
}
