pub mod publish {

    async fn list_peers(swarm: &mut Swarm<NodeBehaviour>){
        println!("Discovered Peers:");
        let nodes = swarm.behaviour().mdns.discovered_nodes();
        let mut unique_peers = HashSet::new();
        for peer in nodes {
            unique_peers.insert(peer);
        }
    
        let all_nodes = Vec::from_iter(unique_peers);
        println!("{:?}", all_nodes);
        println!("Connected to {:?} Nodes!", all_nodes.len());
    }
}