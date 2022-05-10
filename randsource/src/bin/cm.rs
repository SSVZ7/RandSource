
#![allow(dead_code)]
#![allow(unused_variables)]
#[allow(unused_imports)]

// aggregatable dkg imports--------------------------------------------------------
use aggregatable_dkg::{
    dkg::{
        aggregator::DKGAggregator,
        config::Config,
        dealer::Dealer,
        node::Node,
        participant::{Participant, ParticipantState},
        share::DKGTranscript,
        srs::SRS as DKGSRS,
    },
    signature::{
        bls::{srs::SRS as BLSSRS, BLSSignature, BLSSignatureG1, BLSSignatureG2},
        scheme::SignatureScheme,
        algebraic::{keypair::Keypair, public_key::ProvenPublicKey, signature::Signature, srs::SRS as SigSRS},
    },
};
use ark_bls12_381::{Bls12_381, G2Projective};
use ark_ec::ProjectiveCurve;
use ark_ff::UniformRand;
use ark_serialize::*;
use rand::{thread_rng};
use std::{
    error::Error,
    collections::{HashSet, hash_map::DefaultHasher},
    time::{Instant, Duration},
    hash::{Hash, Hasher},
    env,
};

// libp2p imports--------------------------------------------------------
use libp2p::{
    core::upgrade,
    gossipsub::{
        Gossipsub, GossipsubEvent, GossipsubConfigBuilder, 
        GossipsubMessage, IdentTopic as Topic,
        MessageAuthenticity, ValidationMode, MessageId},
    futures::StreamExt,
    identity,
    mdns::{Mdns, MdnsEvent},
    mplex,
    noise,
    swarm::{NetworkBehaviourEventProcess, SwarmEvent, Swarm, SwarmBuilder},
    tcp::TokioTcpConfig,
    NetworkBehaviour, PeerId, Transport,
    multihash::{Code, MultihashDigest},
};
use log::error;
use once_cell::sync::Lazy;
use tokio::{io::AsyncBufReadExt, sync::mpsc};

use rand_beacon::data::{DKGInit, VUFInit, VUFNodeData, VUFNodesData};
use rand_beacon::sig_srs::SigSRSExt;
use rand_beacon::writer::TestResult;

static TOPIC: Lazy<Topic> = Lazy::new(|| Topic::new("dkg"));

// data that gets sent to main loop
pub enum ChannelData{
    Participants(Vec<Participant::<Bls12_381, BLSSignature<BLSSignatureG1<Bls12_381>>>>),
    StartAggregation(String),
    VUFData(VUFInit<Bls12_381>),
    Empty,
}

// Create a custom network behaviour that uses Gossipsub and mDNS
// Only take into account behaviour of Gossipsub and mDNS
#[derive(NetworkBehaviour)]
#[behaviour(event_process = true)]
pub struct NodeBehaviour {
    pub gossipsub: Gossipsub,
    pub mdns: Mdns,

    #[behaviour(ignore)]
    pub response_sender: mpsc::UnboundedSender<ChannelData>,

    #[behaviour(ignore)]
    pub state: usize,

    #[behaviour(ignore)]
    pub start_time: Option<Instant>,

    #[behaviour(ignore)]
    pub dkg_init: Option<DKGInit<Bls12_381>>,

    #[behaviour(ignore)]
    pub cm_id: PeerId,

    #[behaviour(ignore)]
    pub node_id: PeerId,

    #[behaviour(ignore)]
    pub participant_id: usize,

    #[behaviour(ignore)]
    pub node_list: Vec<PeerId>,

    #[behaviour(ignore)]
    pub nodes_received: Vec<PeerId>,

    #[behaviour(ignore)]
    pub participants: Option<Vec<Participant::<Bls12_381, BLSSignature<BLSSignatureG1<Bls12_381>>>>>,

    #[behaviour(ignore)]
    pub dkg_time: Option<Duration>,

    #[behaviour(ignore)]
    pub vuf_data: Option<VUFInit::<Bls12_381>>,

    #[behaviour(ignore)]
    pub vuf_sigs_pks: VUFNodesData::<Bls12_381>,
}

impl NetworkBehaviourEventProcess<GossipsubEvent> for NodeBehaviour{
    // Called when `gossipsub` produces an event.
    fn inject_event(&mut self, message: GossipsubEvent) {
        if let GossipsubEvent::Message{propagation_source, message_id, message} = message {

            if let Ok(a_participant) = Participant::<Bls12_381, BLSSignature<BLSSignatureG1<Bls12_381>>>::deserialize(&*message.data) {
                let received_peer_id: PeerId = message.source.unwrap();
                let received_before = self.nodes_received.iter().any(|&p| p == received_peer_id);

                // If haven't received this participant struct before
                if self.state == 1 && !received_before {
                    self.nodes_received.push(received_peer_id);
                    match self.participants.clone(){
                        Some(ps) => {
                            let mut ps_updated = ps.clone();
                            ps_updated.push(a_participant);
                            ps_updated.sort_by(|a, b| a.id.cmp(&b.id));
                            //ps_updated.iter().for_each(|p| println!("{}", p.id)); 
                            self.participants = Some(ps_updated.clone());
                            
                            // Check if received all participants structs from all nodes
                            let this_dkg_init = self.dkg_init.clone().unwrap();
                            if self.nodes_received.len() == this_dkg_init.num_nodes{
                                self.nodes_received = vec![];
                                stage_channel_data(
                                    self.response_sender.clone(), 
                                    ChannelData::Participants(ps_updated),
                                );
                            }
                        }
                        None => {
                            // Assume 1 node cannot do a DKG on their own
                            let mut ps = Vec::new();
                            ps.push(a_participant);
                            self.participants = Some(ps)
                        }
                    }
                }
            }

            if let Ok(msg) = serde_json::from_slice::<String>(&message.data) {
                let received_peer_id: PeerId = message.source.unwrap();
                let received_before = self.nodes_received.iter().any(|&p| p == received_peer_id);
                match msg.as_str() {
                    "Ready to aggregate" => {
                        if self.state == 2 && !received_before {
                            self.nodes_received.push(received_peer_id);
                            let this_dkg_init = self.dkg_init.clone().unwrap();
                            if self.nodes_received.len() == this_dkg_init.num_nodes {
                                self.nodes_received = [].to_vec();
                                stage_channel_data(
                                    self.response_sender.clone(), 
                                    ChannelData::StartAggregation("Begin Aggregation".to_string()),
                                );
                            }
                        }

                    }
                    "Ready for VUF" => {
                        if self.state == 3 && !received_before {
                            self.nodes_received.push(received_peer_id);
                            let this_dkg_init = self.dkg_init.clone().unwrap();
                            if self.nodes_received.len() == this_dkg_init.num_nodes {
                                self.nodes_received = [].to_vec();
                                self.state = 4;
                                println!("DKG protocol completed.");

                                // get time elapsed from start of DKG
                                let start_time = self.start_time.clone();
                                let this_start_time = start_time.unwrap();
                                let elapsed = this_start_time.elapsed();
                                self.dkg_time = Some(elapsed.clone());
                                println!("Time taken for DKG: {:?}", elapsed);
                            }
                        }
                    }
                    _ => {}
                }
            }

            if let Ok(node_sig) = VUFNodeData::<Bls12_381>::deserialize(&*message.data) {
                let received_peer_id: PeerId = message.source.unwrap();
                let received_before = self
                    .nodes_received.iter()
                    .any(|&p| p == received_peer_id);

                if self.state == 5 && !received_before {
                    self.nodes_received = vec![];
                    let cm_vuf_data = self.vuf_data.clone();
                    let vuf_data = cm_vuf_data.unwrap();
                    let vuf_msg = vuf_data.message;
                    let msg = &vuf_msg[..];

                    let this_proven_pk = node_sig.proven_pk;
                    let this_sig = node_sig.signature;
                                                                                                                                 
                    this_proven_pk.verify().unwrap();
                    this_sig.verify_and_derive(this_proven_pk.clone(), &msg[..]).unwrap();

                    let mut current_proven_pks = self.vuf_sigs_pks.proven_pks.clone();
                    let mut current_sigs = self.vuf_sigs_pks.signatures.clone();
                    current_sigs.push(this_sig);
                    current_proven_pks.push(this_proven_pk); 
                    self.vuf_sigs_pks.signatures = current_sigs.clone();
                    self.vuf_sigs_pks.proven_pks = current_proven_pks.clone();

                    // Threshold of signatures reached
                    let this_dkg_init = self.dkg_init.clone().unwrap();
                    let threshold = this_dkg_init.dkg_config.degree;
                    if self.vuf_sigs_pks.signatures.len() == threshold {
                        let vuf_srs = vuf_data.vuf_srs;
                        let aggregated_pk = ProvenPublicKey::aggregate(&current_proven_pks[0..threshold], 
                            vuf_srs.clone()).unwrap();
                        let aggregated_sig = Signature::aggregate(&current_sigs[0..threshold]).unwrap();

                        let output = aggregated_sig.verify_and_derive(aggregated_pk, msg).unwrap();

                        let mut buffer = Vec::new(); 
                        output.serialize(&mut buffer).unwrap();
                        println!("output={:?}\n", &buffer);

                        // Get time elapsed from start of DKG
                        let start_time = self.start_time.clone();
                        let this_start_time = start_time.unwrap();
                        let elapsed = this_start_time.elapsed();

                        // Hash the buffer containing aggregated signature
                        let to_hash = &buffer[..];
                        let multi_hash = Code::Sha2_256.digest(to_hash);
                        let hash = multi_hash.digest();
                        println!("sha256(output)={:02x?}", hash);
                        println!("Total time taken for VUF: {:?}", elapsed);
                        
                        // Log completion times to a csv file
                        let data = TestResult {
                            n: this_dkg_init.num_nodes.to_string(),
                            dkg_time: self.dkg_time.unwrap().as_secs_f64().to_string(),
                            vuf_time: elapsed.as_secs_f64().to_string()
                        };

                        if let Err(e) = TestResult::write_to_csv(data, "results.csv") {
                            error!("{}", e)
                        }

                        // Reset stored VUF signatures and public keys
                        self.vuf_sigs_pks.signatures = vec![];
                        self.vuf_sigs_pks.proven_pks = vec![];
                        self.state = 4;
                    }
                }
            }
        }
    }
        
}


impl NetworkBehaviourEventProcess<MdnsEvent> for NodeBehaviour {
    // Called when `mdns` produces an event.
    fn inject_event(&mut self, event: MdnsEvent) {
        match event {
            MdnsEvent::Discovered(list) => {
                for (peer, _) in list {
                    self.gossipsub.add_explicit_peer(&peer);
                }
            }
            MdnsEvent::Expired(list) => {
                for (peer, _) in list {
                    if !self.mdns.has_node(&peer) {
                        self.gossipsub.remove_explicit_peer(&peer);
                    }
                }
            }
        }
    }
}

fn stage_channel_data(sender: mpsc::UnboundedSender<ChannelData>, data: ChannelData) {
    tokio::spawn(async move {
        if let Err(e) = sender.send(data) {
            error!("ERROR (Channel data not sent): {}", e);
        }
    });
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>>{
    let mut num_nodes: usize = 3;
    let arg = std::env::args().nth(1);
    match arg{
        Some(n) => {
            num_nodes = n.parse().unwrap();
        },
        _ => {
            panic!("Number of nodes required not found!");
        }
    }
    let degree: usize = (num_nodes + 1)/2;

    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(id_keys.public());
    println!("Local peer id: {:?}", peer_id);

    // setup swarm variables
    let (response_sender, mut response_rcv) = mpsc::unbounded_channel();
    let state: usize = 0;

    // Create a keypair for authenticated encryption of the transport.
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&id_keys)
        .expect("Signing libp2p-noise static DH keypair failed.");

    // Create a tokio-based TCP transport use noise for authenticated
    // encryption and Mplex for multiplexing of substreams on a TCP stream.
    let transport = TokioTcpConfig::new()
        .nodelay(true)
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(mplex::MplexConfig::new())
        .boxed();

    // Create a Swarm to manage peers and events.
    let this_id = peer_id.clone();
    let mut swarm = {
        let mdns = Mdns::new(Default::default()).await?;

        // To content-address message, take H(source||message) as the message id
        let message_id_fn = |message: &GossipsubMessage| {
            let mut h = DefaultHasher::new();
            let mut source = message.source.unwrap().to_bytes();
            let mut data = message.data.clone();
            source.append(&mut data);
            source.hash(&mut h);
            MessageId::from(h.finish().to_string())
        };

        // Set a custom gossipsub
        let gossipsub_config = GossipsubConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(ValidationMode::Strict)
            .message_id_fn(message_id_fn)
            .build()
            .expect("Valid config");

        // Build a gossipsub defined network behaviour
        let gossipsub: Gossipsub =
            Gossipsub::new(MessageAuthenticity::Signed(id_keys), gossipsub_config)
                .expect("Correct configuration");

        let mut behaviour = NodeBehaviour {
            gossipsub,
            mdns,
            response_sender,
            state,
            start_time: None,
            dkg_init: None,
            cm_id: this_id,
            node_id: this_id,
            participant_id: 0,
            node_list: vec![this_id],
            nodes_received: vec![],
            participants: None,
            dkg_time: None,
            vuf_data: None,
            vuf_sigs_pks: VUFNodesData {
                proven_pks: vec![],
                signatures: vec![],
            },
        };

        behaviour.gossipsub.subscribe(&TOPIC).unwrap();

        // We want the connection background tasks to be spawned
        // onto the tokio runtime.
        SwarmBuilder::new(transport, behaviour, peer_id)
            .executor(Box::new(|fut| {
                tokio::spawn(fut);
            }))
            .build()
    };

    // Read full lines from stdin
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();

    // Listen on all interfaces and whatever port the OS assigns
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
  
    loop {
        tokio::select! {
            //received from stdin
            line = stdin.next_line() => {
                let line = line?.expect("stdin closed");
                println!("line: {:?}", &line);
                let input: Vec<&str> = line.as_str().split(" ").collect();
                let first_cmd = input.get(0).unwrap().clone();
                match first_cmd {
                    "start"  => {
                        let start = Instant::now();
                        swarm.behaviour_mut().start_time = Some(start);
                        let peers = handle_list_peers(&mut swarm, &num_nodes).await;
                        init_dkg(degree, num_nodes, peers, &mut swarm).await;
                    },
                    "sign" => {
                        let start = Instant::now();
                        swarm.behaviour_mut().start_time = Some(start);
                        let to_sign = input.get(1..input.len()); 
                        match to_sign {
                            Some(msg) => {
                                let data: String = msg.join(" ");
                                println!("msg={}", data);
                                init_vuf(data.as_bytes().to_vec(), &mut swarm).await;
                            }
                            None => {
                                println!("ERROR: No message to sign found!");
                            }
                        }
                    },
                    "check" => {
                        check_state(&mut swarm).await;
                    },
                    "l" => {
                        handle_list_peers(&mut swarm, &num_nodes).await;
                    },
                    _ => {},
                }
            }
            
            // received from the channel
            response = response_rcv.recv() => {
                match response {
                    Some(ChannelData::Participants(participants)) => {
                        println!("Participants being sent to nodes");
                        send_participants(participants, &mut swarm).await;
                    }
                    Some(ChannelData::StartAggregation(msg)) => {
                        println!("Start agg. msg being sent to nodes");
                        send_message(msg, &mut swarm, 2, 3).await;
                    }
                    //Some(ChannelData::VUFData(vuf_init)) => {
                    //    println!("vuf_init data being sent to nodes");
                    //    send_vuf_init(vuf_init, &mut swarm).await;
                    //}
                    _ => {}
                }
            }

            //event on the swarm
            event = swarm.select_next_some() => {
                if let SwarmEvent::NewListenAddr {address, .. } = event {
                    println!("Listening on {:?}", address);
                }
            }
        }
    }
    
}

async fn handle_list_peers(
    swarm: &mut Swarm<NodeBehaviour>, 
    num_nodes: &usize
) -> Vec<Vec<u8>>{
    println!("Discovered Peers:");
    let nodes = swarm.behaviour().mdns.discovered_nodes();
    let mut bytes = vec![];
    let mut unique_peers = HashSet::new();
    for peer in nodes {
        unique_peers.insert(peer);
    }

    let all_nodes = Vec::from_iter(unique_peers);
    println!("{:?}", all_nodes);
    println!("Connected to {:?} Nodes!", all_nodes.len());
    //assert_eq!(all_nodes.len(), *num_nodes);
    all_nodes.iter().for_each(|p| bytes.push(p.to_bytes())); 
    bytes
}

// for debugging purposes
async fn check_state(swarm: &mut Swarm<NodeBehaviour>) {
    println!("Checking state");
    let behaviour = swarm.behaviour_mut();
    println!("This node's state is {}", behaviour.state);
}


// cm runs this when all nodes connected
async fn init_dkg(
    degree: usize, 
    num_nodes: usize, 
    connected_peers: Vec<Vec<u8>>, 
    swarm: &mut Swarm<NodeBehaviour>
){
    let behaviour = swarm.behaviour_mut();
    if behaviour.state != 0 {
        return
    }

    println!("This config manager is starting the DKG!");
    let rng = &mut thread_rng();
    let dkg_srs = DKGSRS::<Bls12_381>::setup(rng).unwrap();
    let u_1 = G2Projective::rand(rng).into_affine();

    let dkg_config = Config {
        srs: dkg_srs.clone(),
        u_1,
        degree: degree,
    };

    let cm_dkg_init = DKGInit {
        num_nodes: num_nodes,
        peers: connected_peers,
        dkg_config: dkg_config,
    };

    let mut buffer = Vec::new(); 
    cm_dkg_init.serialize(&mut buffer).unwrap();
    
    if let Err(e) = behaviour.gossipsub.publish(TOPIC.clone(), buffer){
        error!("ERROR: DKGInit not published! {:?}", e);
    }

    behaviour.state = 1;
    behaviour.dkg_init = Some(cm_dkg_init);

}

async fn send_participants(
    participants: Vec<Participant::<Bls12_381, BLSSignature<BLSSignatureG1<Bls12_381>>>>, 
    swarm: &mut Swarm<NodeBehaviour>
){
    let behaviour = swarm.behaviour_mut();

    let sz = participants.serialized_size();
    //println!("This Size(Participants)={:?}", sz);
    let mut buffer = Vec::new(); 
    participants.serialize(&mut buffer).unwrap();
    
    if behaviour.state == 1 {
        if let Err(e) = behaviour.gossipsub.publish(TOPIC.clone(), buffer){
            error!("ERROR: Participants not published! {:?}", e);
        }
        behaviour.state = 2;
    }
}

async fn send_message(
    msg: String,
    swarm: &mut Swarm<NodeBehaviour>,
    start_state: usize,
    end_state: usize
){
    let behaviour = swarm.behaviour_mut();
    let json_data = serde_json::to_string(&msg).expect("Can't serialize to json!");
    
    if behaviour.state == start_state {
        if let Err(e) = behaviour.gossipsub.publish(TOPIC.clone(), json_data.as_bytes()){
            error!("ERROR: Message not published! {:?}", e);
        }
        behaviour.state = end_state;
    }
}

async fn init_vuf(
    vuf_msg: Vec<u8>,
    swarm: &mut Swarm<NodeBehaviour>,
){
    let behaviour = swarm.behaviour_mut();
    if behaviour.state != 4 {
        return
    }
    println!("This config manager is starting the VUF!");

    let rng = &mut thread_rng();
    let this_dkg_init = behaviour.dkg_init.clone().unwrap();
    let dkg_srs = this_dkg_init.dkg_config.srs.clone();
    let vuf_srs = SigSRS::<Bls12_381>::setup_from_dkg(rng, dkg_srs.clone()).unwrap();

    let vuf_init = VUFInit {
        vuf_srs: vuf_srs,
        message: vuf_msg,
    };
    behaviour.vuf_data = Some(vuf_init.clone());
    
    let mut buffer = Vec::new(); 
    vuf_init.serialize(&mut buffer).unwrap();
    
    if behaviour.state == 4{
        if let Err(e) = behaviour.gossipsub.publish(TOPIC.clone(), buffer){
            error!("ERROR: VUFInit not published! {:?}", e);
        }
        behaviour.state = 5;
    }
}