#[cfg(test)]
pub mod tests;

use algebra::{fields::mnt4753::Fr as MNT4Fr, curves::mnt6753::G1Projective as MNT6G1Projective, Field, PrimeField, ToBits};
use primitives::{
    signature::schnorr::field_based_schnorr::FieldBasedSchnorrSignature,
    crh::MNT4PoseidonHash,
};
use r1cs_crypto::{
    signature::{
        schnorr::field_based_schnorr::{FieldBasedSchnorrSigGadget, FieldBasedSchnorrSigVerificationGadget},
        FieldBasedSigGadget,
    },
    crh::{MNT4PoseidonHashGadget, FieldBasedHashGadget},
};

use r1cs_std::{groups::curves::short_weierstrass::mnt::mnt6::mnt6753::MNT6G1Gadget, fields::{
    fp::FpGadget, FieldGadget,
}, alloc::AllocGadget, bits::{
    boolean::Boolean, FromBitsGadget,
}, eq::EqGadget, Assignment};

use r1cs_core::{ConstraintSystem, ConstraintSynthesizer, SynthesisError};

use crate::constants::NaiveThresholdSigParams;

use std::marker::PhantomData;
use std::cell::RefCell;
use rand::rngs::OsRng;

thread_local!(pub static NULL_CONST: RefCell<NaiveThresholdSigParams> = RefCell::new(NaiveThresholdSigParams::new()));

//Sig types
type SchnorrSigGadget = FieldBasedSchnorrSigGadget<MNT4Fr>;
type SchnorrVrfySigGadget = FieldBasedSchnorrSigVerificationGadget<
    MNT4Fr, MNT6G1Projective, MNT6G1Gadget, MNT4PoseidonHash, MNT4PoseidonHashGadget
>;

//Field types
type MNT4FrGadget = FpGadget<MNT4Fr>;

pub struct NaiveTresholdSignature<F: PrimeField>{

    //Witnesses
    pks:                      Vec<Option<MNT6G1Projective>>, //pk_n = g^sk_n
    sigs:                     Vec<Option<FieldBasedSchnorrSignature<MNT4Fr>>>, //sig_n = sign(sk_n, H(MR(BT), BH(Bi-1), BH(Bi)))
    threshold:                Option<MNT4Fr>,
    b:                        Vec<Option<bool>>,
    end_epoch_mc_b_hash:      Option<MNT4Fr>,
    prev_end_epoch_mc_b_hash: Option<MNT4Fr>,
    mr_bt:                    Option<MNT4Fr>,

    //Other
    max_pks:                  usize,
    _field:                   PhantomData<F>,
}

impl<F: PrimeField>NaiveTresholdSignature<F> {
    pub fn new(
        pks:                      Vec<MNT6G1Projective>,
        sigs:                     Vec<Option<FieldBasedSchnorrSignature<MNT4Fr>>>,
        threshold:                MNT4Fr,
        b:                        MNT4Fr,
        end_epoch_mc_b_hash:      MNT4Fr,
        prev_end_epoch_mc_b_hash: MNT4Fr,
        mr_bt:                    MNT4Fr,
        max_pks:                  usize,
    ) -> Self {

        //Convert b to the needed bool vector
        let b_bool = {
            let log_max_pks = (max_pks.next_power_of_two() as u64).trailing_zeros() as usize;
            let b_bits = b.write_bits();
            let to_skip = MNT4Fr::size_in_bits() - (log_max_pks + 1);
            b_bits[to_skip..].to_vec().iter().map(|&b| Some(b)).collect::<Vec<_>>()
        };
        Self{
            pks: pks.iter().map(|&pk| Some(pk)).collect::<Vec<_>>(),
            sigs,
            threshold: Some(threshold),
            b: b_bool,
            end_epoch_mc_b_hash:      Some(end_epoch_mc_b_hash),
            prev_end_epoch_mc_b_hash: Some(prev_end_epoch_mc_b_hash),
            mr_bt:                    Some(mr_bt),
            max_pks,
            _field: PhantomData
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<MNT4Fr> for NaiveTresholdSignature<F> {
    fn generate_constraints<CS: ConstraintSystem<MNT4Fr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {

        //Internal checks
        let log_max_pks = (self.max_pks.next_power_of_two() as u64).trailing_zeros() as usize;
        assert_eq!(self.max_pks, self.pks.len());
        assert_eq!(self.max_pks, self.sigs.len());
        assert_eq!(log_max_pks + 1, self.b.len());

        //Check pks are consistent with self.hash_commitment

        //Allocate public keys as witnesses
        let mut pks_g = Vec::with_capacity(self.max_pks);

        for (i, pk) in self.pks.iter().enumerate() {
            // It's safe to not perform any check when allocating the pks,
            // considering that the pks are hashed, so they should be public
            // at some point, therefore verifiable by everyone.
            let pk_g = MNT6G1Gadget::alloc_without_check(
                cs.ns(|| format!("alloc_pk_{}", i)),
                || pk.ok_or(SynthesisError::AssignmentMissing)
            )?;
            pks_g.push(pk_g);
        }

        //Enforce pks_threshold_hash
        let mut pks_threshold_hash_g = MNT4PoseidonHashGadget::check_evaluation_gadget(
            cs.ns(|| "hash public keys"),
            pks_g.iter().map(|pk| pk.x.clone()).collect::<Vec<_>>().as_slice(),
        )?;

        //Allocate threshold as witness
        let t_g = MNT4FrGadget::alloc(
            cs.ns(|| "alloc threshold"),
            || self.threshold.ok_or(SynthesisError::AssignmentMissing)
        )?;

        pks_threshold_hash_g = MNT4PoseidonHashGadget::check_evaluation_gadget(
            cs.ns(|| "H(H(pks), threshold)"),
            &[pks_threshold_hash_g, t_g.clone()],
        )?;

        //Check signatures

        //Reconstruct message as H(MR(BT), BH(Bi-1), BH(Bi))
        let mr_bt_g = MNT4FrGadget::alloc(
            cs.ns(|| "alloc mr_bt"),
            || self.mr_bt.ok_or(SynthesisError::AssignmentMissing)
        )?;

        let prev_end_epoch_mc_block_hash_g = MNT4FrGadget::alloc(
            cs.ns(|| "alloc prev_end_epoch_mc_block_hash"),
            || self.prev_end_epoch_mc_b_hash.ok_or(SynthesisError::AssignmentMissing)
        )?;

        let end_epoch_mc_block_hash_g = MNT4FrGadget::alloc(
            cs.ns(|| "alloc end_epoch_mc_block_hash"),
            || self.end_epoch_mc_b_hash.ok_or(SynthesisError::AssignmentMissing)
        )?;

        let message_g = MNT4PoseidonHashGadget::check_evaluation_gadget(
            cs.ns(|| "H(MR(BT), BH(i-1), BH(i))"),
            &[mr_bt_g.clone(), prev_end_epoch_mc_block_hash_g.clone(), end_epoch_mc_block_hash_g.clone()],
        )?;

        let mut sigs_g = Vec::with_capacity(self.max_pks);

        //Allocate signatures as witnesses
        for (i, sig) in self.sigs.iter().enumerate() {
            let sig_g = SchnorrSigGadget::alloc(
                cs.ns(|| format!("alloc_sig_{}", i)),
                || sig.ok_or(SynthesisError::AssignmentMissing)
            )?;
            sigs_g.push(sig_g);
        }

        let mut verdicts = Vec::with_capacity(self.max_pks);

        //Check signatures verification verdict on message
        for (i ,(pk_g, sig_g))
            in pks_g.iter().zip(sigs_g.iter()).enumerate() {

            let v = SchnorrVrfySigGadget::enforce_signature_verdict(
                cs.ns(|| format!("check_sig_verdict_{}", i)),
                pk_g,
                sig_g,
                &[message_g.clone()],
            )?;
            verdicts.push(v);
        }

        //Count valid signatures
        let mut valid_signatures = MNT4FrGadget::zero(cs.ns(|| "alloc valid signatures count"))?;
        for (i, v) in verdicts.iter().enumerate() {
            valid_signatures = valid_signatures.conditionally_add_constant(
                cs.ns(|| format!("add_verdict_{}", i)),
                v,
                MNT4Fr::one(),
            )?;
        }

        //Enforce wcert_sysdata_hash
        let wcert_sysdata_hash_g = MNT4PoseidonHashGadget::check_evaluation_gadget(
            cs.ns(|| "H(valid_signatures, MR(BT), BH(i-1), BH(i))"),
            &[valid_signatures.clone(), mr_bt_g, prev_end_epoch_mc_block_hash_g, end_epoch_mc_block_hash_g]
        )?;

        //Check pks_threshold_hash and wcert_sysdata_hash

        let actual_aggregated_input = MNT4PoseidonHashGadget::check_evaluation_gadget(
            cs.ns(|| "H(pks_threshold_hash, wcert_sysdata_hash)"),
            &[pks_threshold_hash_g, wcert_sysdata_hash_g]
        )?;

        let expected_aggregated_input = MNT4FrGadget::alloc_input(
            cs.ns(|| "alloc aggregated input"),
            || {
                let aggregated_input_val = actual_aggregated_input.get_value().get()?;
                Ok(aggregated_input_val)
            }
        )?;

        expected_aggregated_input.enforce_equal(
            cs.ns(|| "check aggregated input"),
            &actual_aggregated_input
        )?;

        //Alloc the b's as witnesses
        let mut bs_g = Vec::with_capacity(log_max_pks + 1);
        for (i, b) in self.b.iter().enumerate(){
            let b_g = Boolean::alloc(
                cs.ns(|| format!("alloc b_{}", i)),
                || b.ok_or(SynthesisError::AssignmentMissing)
            )?;
            bs_g.push(b_g);
        }

        //Pack the b's into a field element
        let b_field = MNT4FrGadget::from_bits(
            cs.ns(|| "pack the b's into a field element"),
            bs_g.as_slice(),
        )?;

        //Enforce threshold
        valid_signatures
            .sub(cs.ns(|| "valid_signatures - threshold"), &t_g)?
            .enforce_equal(cs.ns(|| "threshold check"), &b_field)?;

        Ok(())
    }
}

use algebra::curves::mnt4753::MNT4;
use proof_systems::groth16::{Parameters, generator::generate_random_parameters};

#[allow(dead_code)]
pub fn generate_parameters(max_pks: usize) -> Result<Parameters<MNT4>, SynthesisError> {

    //Istantiating rng
    let mut rng = OsRng::default();

    //Istantiating supported number of pks and sigs
    let log_max_pks = (max_pks.next_power_of_two() as u64).trailing_zeros() as usize;

    // Create parameters for our circuit
    let c = NaiveTresholdSignature::<MNT4Fr> {
        pks:                      vec![None; max_pks],
        sigs:                     vec![None; max_pks],
        threshold:                None,
        b:                        vec![None; log_max_pks + 1],
        end_epoch_mc_b_hash:      None,
        prev_end_epoch_mc_b_hash: None,
        mr_bt:                    None,
        max_pks,
        _field:                   PhantomData
    };

    let params = generate_random_parameters::<MNT4, _, _>(c, &mut rng);
    params
}

#[cfg(test)]
mod test {
    use super::*;
    use algebra::{curves::mnt4753::MNT4, BigInteger768, ProjectiveCurve};
    use primitives::{
        crh::FieldBasedHash,
        signature::{
            FieldBasedSignatureScheme, schnorr::field_based_schnorr::FieldBasedSchnorrSignatureScheme,
        },
    };
    use proof_systems::groth16::{
        Parameters,
        Proof, create_random_proof,
        prepare_verifying_key, verify_proof,
    };
    use rand::{
        Rng, rngs::OsRng
    };

    type SchnorrSig = FieldBasedSchnorrSignatureScheme<MNT4Fr, MNT6G1Projective, MNT4PoseidonHash>;

    fn generate_test_proof(
        max_pks:                  usize,
        valid_sigs:               usize,
        threshold:                usize,
        wrong_pks_threshold_hash: bool,
        wrong_wcert_sysdata_hash: bool,
        params:                   Parameters<MNT4>,
    ) -> Result<(Proof<MNT4>, Vec<MNT4Fr>), SynthesisError> {

        //Istantiate rng
        let mut rng = OsRng::default();

        //Generate message to sign
        let mr_bt: MNT4Fr = rng.gen();
        let prev_end_epoch_mc_b_hash: MNT4Fr = rng.gen();
        let end_epoch_mc_b_hash: MNT4Fr = rng.gen();
        let message = MNT4PoseidonHash::evaluate(&[mr_bt, prev_end_epoch_mc_b_hash, end_epoch_mc_b_hash]).unwrap();

        //Generate another random message used to simulate a non-valid signature
        let invalid_message: MNT4Fr = rng.gen();

        let mut pks = vec![];
        let mut sigs = vec![];

        for _ in 0..valid_sigs {
            let (pk, sk) = SchnorrSig::keygen(&mut rng);
            let sig = SchnorrSig::sign(&mut rng, &pk, &sk, &[message]).unwrap();
            pks.push(pk);
            sigs.push(Some(sig));
        }

        NULL_CONST.with(|nc| {
            let nc = *nc.borrow();
            for _ in 0..(max_pks-valid_sigs){
                //Sample a random boolean and decide if generating a non valid signature or a null one
                let generate_null: bool = rng.gen();
                let (pk, sig) = if generate_null {
                    (nc.null_pk, nc.null_sig)
                } else {

                    let (pk, sk) = SchnorrSig::keygen(&mut rng);
                    let sig = SchnorrSig::sign(&mut rng, &pk, &sk, &[invalid_message]).unwrap();
                    (pk, sig)
                };
                pks.push(pk);
                sigs.push(Some(sig));
            }
        });
        //Generate b
        let t_field = MNT4Fr::from_repr(BigInteger768::from(threshold as u64));
        let valid_field = MNT4Fr::from_repr(BigInteger768::from(valid_sigs as u64));
        let b_field = valid_field - &t_field;

        //Compute pks_threshold_hash
        let pks_hash_input = pks.iter().map(|pk| pk.into_affine().x).collect::<Vec<_>>();
        let pks_hash = MNT4PoseidonHash::evaluate(pks_hash_input.as_slice()).unwrap();
        let pks_threshold_hash = if !wrong_pks_threshold_hash {
            MNT4PoseidonHash::evaluate(&[pks_hash, t_field]).unwrap()
        } else {
            rng.gen()
        };

        //Compute wcert_sysdata_hash
        let wcert_sysdata_hash = if !wrong_wcert_sysdata_hash {
            MNT4PoseidonHash::evaluate(&[valid_field, mr_bt, prev_end_epoch_mc_b_hash, end_epoch_mc_b_hash]).unwrap()
        } else {
            rng.gen()
        };

        let aggregated_input = MNT4PoseidonHash::evaluate(&[pks_threshold_hash, wcert_sysdata_hash]).unwrap();

        //Create proof for our circuit
        let c = NaiveTresholdSignature::<MNT4Fr>::new(
            pks, sigs, t_field, b_field, end_epoch_mc_b_hash,
            prev_end_epoch_mc_b_hash, mr_bt, max_pks,
        );

        //Return proof and public inputs if success
        let start = std::time::Instant::now();
        let proof = match create_random_proof(c, &params, &mut rng) {
            Ok(proof) => {
                let public_inputs = vec![aggregated_input];
                Ok((proof, public_inputs))
            }
            Err(e) => Err(e)
        };
        println!("Proof creation time: {:?}", start.elapsed());
        proof
    }

    #[test]
    fn test_naive_threshold_circuit() {
        let n = 6;
        let params = generate_parameters(n).unwrap();
        let pvk = prepare_verifying_key(&params.vk);

        //Generate proof with correct witnesses and v > t
        let (proof, public_inputs) =
            generate_test_proof(n, 5, 4, false, false, params.clone()).unwrap();
        assert!(verify_proof(&pvk, &proof, public_inputs.as_slice()).unwrap());

        //Generate proof with insufficient valid signatures
        let (proof, public_inputs) =
            generate_test_proof(n, 4, 5, false, false, params.clone()).unwrap();
        assert!(!verify_proof(&pvk, &proof, public_inputs.as_slice()).unwrap());

        //Generate proof with bad pks_threshold_hash
        let (proof, public_inputs) =
            generate_test_proof(n, 5, 4, true, false, params.clone()).unwrap();
        assert!(!verify_proof(&pvk, &proof, public_inputs.as_slice()).unwrap());

        //Generate proof with bad wcert_sysdata_hash
        let (proof, public_inputs) =
            generate_test_proof(n, 5, 4, false, true, params.clone()).unwrap();
        assert!(!verify_proof(&pvk, &proof, public_inputs.as_slice()).unwrap());
    }
}