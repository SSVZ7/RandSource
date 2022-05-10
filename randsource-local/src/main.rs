use aggregatable_dkg::{
    dkg::{
        aggregator::DKGAggregator,
        config::Config,
        dealer::Dealer,
        node::Node,
        participant::Participant,
        share::DKGTranscript,
        srs::SRS as DkgSRS,
    },
    signature::{
        bls::{srs::SRS as BLSSRS, BLSSignature, BLSSignatureG1, BLSSignatureG2},
        scheme::SignatureScheme,
        algebraic::{keypair::Keypair, public_key::ProvenPublicKey, signature::Signature, srs::SRS as SigSRS},
    },
};
use ark_bls12_381::{Bls12_381, G2Projective};
use ark_ec::ProjectiveCurve;
use ark_ff::{UniformRand, Zero};
use ark_serialize::*;
use rand::{thread_rng};
use std::{marker::PhantomData, env, time::Instant};
use sha2::{Sha256, Digest};
use log::error;

// use extra functions we created
use randsource_local::sig_srs::{SigSRSExt, KeypairExt};
use randsource_local::keys::NodeExt;
use randsource_local::writer::TestResult;

fn dkg_vuf_runthrough(n: usize) {
    let dkg_start = Instant::now();
    let rng = &mut thread_rng();
    let dkg_srs = DkgSRS::<Bls12_381>::setup(rng).unwrap();

    let bls_sig = BLSSignature::<BLSSignatureG1<Bls12_381>> {
        srs: BLSSRS {
            g_public_key: dkg_srs.h_g2,
            g_signature: dkg_srs.g_g1,
        },
    };
    let bls_pok = BLSSignature::<BLSSignatureG2<Bls12_381>> {
        srs: BLSSRS {
            g_public_key: dkg_srs.g_g1,
            g_signature: dkg_srs.h_g2,
        },
    };

    let u_1 = G2Projective::rand(rng).into_affine();
    let degree = (n + 1)/2;
    //println!("degree={}", degree);

    //CM sends this
    let dkg_config = Config {
        srs: dkg_srs.clone(),
        u_1,
        degree: degree,
    };

    //each node generates their dealer struct
    let mut dealers = vec![];
    for i in 0..n {
        let dealer_keypair_sig = bls_sig.generate_keypair(rng).unwrap();
        let participant = Participant {
            pairing_type: PhantomData,
            id: i,
            public_key_sig: dealer_keypair_sig.1,
            //state: ParticipantState::Dealer,
            state: 0,
        };
        let dealer = Dealer {
            private_key_sig: dealer_keypair_sig.0,
            accumulated_secret: G2Projective::zero().into_affine(),
            participant,
        };

        dealers.push(dealer);
    }

    // send to config manager and they do this for all participants
    // collect clones of dealer.participant into a vector
    let participants = dealers
        .iter()
        .map(|d| d.participant.clone())
        .collect::<Vec<_>>(); 
    let num_participants = participants.len();
    assert_eq!(num_participants, n);
    
    // each node computes their Node struct
    let mut nodes = vec![];
    for i in 0..n {
        let degree = dkg_config.degree;
        let node = Node {
            aggregator: DKGAggregator {
                config: dkg_config.clone(),
                scheme_pok: bls_pok.clone(),
                scheme_sig: bls_sig.clone(),
                participants: participants.clone().into_iter().enumerate().collect(),
                transcript: DKGTranscript::empty(degree, num_participants),
            },
            dealer: dealers[i].clone(),
        };
        nodes.push(node);
    }

    // "gossip phase" - for each node, each other node receives a share from it
    for i in 0..n {
        let node = &mut nodes[i];
        let share = node.share(rng).unwrap();
        for j in 0..n {
            if i == j{
                continue;
            }
            nodes[j]
                .receive_share_and_decrypt(rng, share.clone())
                .unwrap();
        }
    }

    //master pk - G1Affine
    let _master_pk = nodes[0].get_master_public_key().unwrap();

    //node's pk - G1Affine
    let mut pks = vec![];
    for i in 0..num_participants {
        let pk = nodes[i].get_public_key().unwrap();
        //println!("node{}'s pk: {:?}\n", i, &pk);
        pks.push(pk);
    }

    //sk - G2Affine
    let mut sks = vec![];
    for i in 0..n {
        let sk = nodes[i].get_secret_key_share().unwrap();
        sks.push(sk);
    }
    let dkg_elapsed = dkg_start.elapsed();

    //--------------------------------------------------------------------------------
    //VUF
    let vuf_start = Instant::now();
    
    //cm needs to send this
    let vuf_srs = SigSRS::<Bls12_381>::setup_from_dkg(rng, dkg_srs.clone()).unwrap();
    let message = b"hello";

    //each node computes a keypair based on the VUF SRS + public key
    let mut keypairs = vec![];
    let mut proven_public_keys = vec![];
    for i in 0..n {
        let keypair = Keypair::generate_keypair_from_dkg(rng, vuf_srs.clone(), pks[i], sks[i]).unwrap();
        let proven_public_key = keypair.prove_key().unwrap();

        keypairs.push(keypair);
        proven_public_keys.push(proven_public_key);
    }

    //each node signs a message using thier private key
    // other nodes can verify this sigature against the public key of the node that made it    
    let mut signatures = vec![];
    for i in 0..n {
        let signature = keypairs[i].sign(&message[..]).unwrap();

        proven_public_keys[i].verify().unwrap();
        signature
            .verify_and_derive(proven_public_keys[i].clone(), &message[..])      
            .unwrap();
        signatures.push(signature);
    }

    //agrregation step
    let threshold = degree;

    let aggregated_pk =
        ProvenPublicKey::aggregate(&proven_public_keys[0..threshold], vuf_srs.clone())
            .unwrap();

    let aggregated_sig = Signature::aggregate(&signatures[0..threshold]).unwrap();
    let output = aggregated_sig.verify_and_derive(aggregated_pk, message).unwrap();
    let vuf_elapsed = vuf_start.elapsed();

    let mut output_buf: Vec<u8> = Vec::new(); 
    output.serialize(&mut output_buf).unwrap();
    //println!("output={:?}\n", output_buf);

    let mut hasher = Sha256::new();
    hasher.update(&output_buf);
    let result = hasher.finalize();
    println!("sha256(output)= {:?}", result);

    println!("Time taken for DKG protocol: {:?}", dkg_elapsed.as_secs_f64());
    println!("Time taken for VUF protocol: {:?}", vuf_elapsed.as_secs_f64());

    let data = TestResult {
        n: n.to_string(),
        dkg_time: dkg_elapsed.as_secs_f64().to_string(),
        vuf_time: vuf_elapsed.as_secs_f64().to_string()
    };

    if let Err(e) = TestResult::write_to_csv(data, "local_results.csv") {
        error!("{}", e)
    }
}


fn main() {
    match env::args().nth(1) {
        Some(arg1) => {
            if let Ok(n) = arg1.parse::<usize>() {
                dkg_vuf_runthrough(n);
            }else{
                println!("Put the number of nodes as an integer command line argument")
            }
        }
        _ => println!("Put the number of nodes as a command line argument"),
    }
}
