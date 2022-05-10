#!/bin/bash

n=$1
echo "$n nodes"

x=1
while [ $x -le $n ]
do
  echo "Testing with $x nodes"
  for i in $(seq 3)
  do
    echo "Test no. $i"
    ./local $x
  done

  x=$(( $x + 2 ))
done

echo "All tests complete"
