#!/bin/bash

n=$1

for i in $(seq $n)
do
  echo "Starting node $i"
  #RUST_LOG="error" cargo run --bin rand-beacon &
  ./rb-node &
done

echo "All nodes started"


# kill all running nodes and the config manager
#ps -ef | grep rb-node | grep -v grep | awk '{print $2}' | xargs kill
