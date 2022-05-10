# RandSource

## Project Structure

### Aggregatable DKG and VUF
The library originally by Kobi Gurkan, available [here](https://github.com/kobigurk/aggregatable-dkg).
Some adjustments have been made to suit the needs of this project.

### RandSource-local
The local implementation of RandSource 

### RandSource
Contains the distributed implementation of the RandSource protocol.

### Tests
Contains the tests used to evaluate RandSource.

## System Manual

### Running RandSource-local
To run the local implementation:
* Run `cargo run n` where n is the number of nodes used to simulate the protocol

To build the release binary (with compiler optimizations) 
* Run `cargo build --release && cp ./target/release/randsource-local local`
* Run `local n` where n is the number of nodes used to simulate the protocol

### Running RandSource
To run the distributed implementation with the dev profile:
* Compile the config manager and node binaries with `cargo build`
* Copy the binaries `cp ./target/debug/cm cm && cp ./target/debug/node rb-node` 
* To start the nodes use the shell script `rand_beacon.sh` by running `sh rand_beacon.sh n` where n is the number of nodes wish to be run
* In a seperate terminal, start a config manager by running `./cm n` where n is the number of nodes running 

To run the distributed implementation with the release profile:
* Compile the config manager and node binaries with `cargo build --release`
* Copy the binaries `cp ./target/release/cm cm && cp ./target/release/node rb-node` 
* To start the nodes use the shell script `rand_beacon.sh` by running `sh rand_beacon.sh n` where n is the number of nodes wish to be run
* In a seperate terminal, start a config manager by running `./cm n` where n is the number of nodes running 

The nodes run in the background so they cannot directly be interacted with. On the other hand, the config manager can be interacted with.

The RandSource system can be interacted with via the config manager:
* Run `ls` to check the PeerIDs of nodes that the config manager has discovered and the number of nodes discovered
* Run `start` to start the DKG (use the `ls` command to check that the config manager has discovered all of the nodes on the network before starting the DKG)
* To get the randomnes output, once the DKG has completed, run `sign message` to sign an arbitrary message of the user's choice, the message can include spaces
* More messages can be signed, for more randomness outputs by running `sign message`
* For debugging purposes, it might be useful to check the state of the config manager use the `check` command
* Once the system has been used, all the nodes can be terminated: `ps -ef | grep rb-node | grep -v grep | awk '{print $2}' | xargs kill`

RandSource can run fully distributed, the distributed system can run on several machines as long as the machines are all on the same LAN. Please note it may take a few minutes for all nodes to discover each other.