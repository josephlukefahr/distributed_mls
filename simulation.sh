#!/bin/bash

FACTORS=(3 5 10)
NUM_TRIALS=10

THIS_DIR="$(pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
for i in ${FACTORS[@]}; do
  for j in $(seq 0 $NUM_TRIALS); do
    cargo run --example simulation_trace -- -n $i --seed $j >> "$THIS_DIR/simulation_trace_${i}_${j}.csv"
    cargo run --example simulation_summary -- -n $i --seed $j >> "$THIS_DIR/simulation_summary.csv"
  done
done
cd "$THIS_DIR"
