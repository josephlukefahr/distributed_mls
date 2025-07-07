//! Deterministic simulation of DMLS execution.
//!
//! This example simulates a distributed MLS (DMLS) environment with multiple participants.
//! It initializes a group of participants, processes updates, and handles message broadcasting and delivery.
//! It uses a random number generator to determine the order of events, simulating an asynchronous network where messages are sent and received in a non-deterministic manner such that timing of message delivery cannot be predicted.
//! Events are uniformly selected from a queue, and each event is processed in a loop until all events are handled.
//! The simulation tracks the number of messages sent and received, as well as the total bytes sent and received.

use distributed_mls::{DistributedMlsAgent, DistributedMlsError, ProcessOutcome};
use mls_rs::MlsMessage;
use mls_rs_codec::MlsSize;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use std::collections::HashMap;

use md5 as _;
use mls_rs_crypto_openssl as _;

#[derive(Debug)]
enum Event {
    Broadcast(u16, MlsMessage),
    Receive(u16, MlsMessage),
    Encrypt(u16, String, String),
    Process(u16),
    Add(u16, MlsMessage),
    Update(u16),
}

/// struct for command-line arguments
#[derive(clap::Parser, Debug)]
struct CliArgStruct {
    /// number of participants
    #[arg(short, long, default_value_t = 3)]
    num_participants: u16,
    /// seed for rng
    #[arg(long, default_value_t = 0)]
    seed: u64,
    // exporter length
    #[arg(long, default_value_t = 32)]
    exporter_length: usize,
}

fn main() {
    // parse cli args
    let args: CliArgStruct = clap::Parser::parse();
    // rng
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(args.seed);
    // event queue
    let mut events = Vec::new();
    // participants
    let mut agents = Vec::new();
    // counters
    let mut messages_sent = 0;
    let mut messages_received = 0;
    let mut bytes_sent = 0;
    let mut bytes_received = 0;
    let mut event_counter = 0;
    let mut process_counter = 0;
    // create participants
    for i in 0..args.num_participants {
        println!("\nCREATING PARTICIPANT {i}");
        match DistributedMlsAgent::new(i.to_be_bytes().to_vec(), args.exporter_length) {
            Ok(agent) => {
                agents.push(agent);
            }
            Err(e) => {
                println!("**FAILED: {e}");
            }
        }
    }
    // seed initialization events & run in phases
    for phase in 0..3 {
        println!("\n=== PHASE {phase} ===");
        // seed events by phase
        match phase {
            0 => {
                // phase 0: everyone adds everyone else
                for i in 0..agents.len() as u16 {
                    for j in 0..agents.len() as u16 {
                        if j != i {
                            println!("\nSEEDING EVENT: PARTICIPANT {i} ADDS {j}");
                            match agents
                                .get(j as usize)
                                .unwrap()
                                .generate_key_package_message()
                            {
                                Ok(key_package_message) => {
                                    // push add event
                                    events.push(Event::Add(i, key_package_message));
                                }
                                Err(e) => {
                                    println!("**FAILED: {e}");
                                }
                            }
                        }
                    }
                }
            }
            1 => {
                // phase 1: everyone updates and broadcasts a message
                for i in 0..agents.len() as u16 {
                    println!("\nSEEDING EVENT: PARTICIPANT {i} ENCRYPTS MESSAGE");
                    events.push(Event::Encrypt(
                        i,
                        format!("Hello, world, from participant {i}!"),
                        format!("Test AAD!"),
                    ));
                }
            }
            2 => {
                // phase 2: everyone updates and broadcasts a message
                for i in 0..agents.len() as u16 {
                    println!("\nSEEDING EVENT: PARTICIPANT {i} UPDATES");
                    events.push(Event::Update(i));
                }
            }
            _ => {}
        }
        // run the current phase of simulation
        while !events.is_empty() {
            // pull next event; this is a uniform random selection
            let event = events.remove(rng.next_u64() as usize % events.len());
            // log
            println!("\nHANDLING EVENT: {event:?}");
            // handle event
            match event {
                Event::Broadcast(i, message) => {
                    // log
                    messages_sent += 1;
                    bytes_sent += message.mls_encoded_len();
                    // broadcast message to all participants
                    for j in 0..agents.len() as u16 {
                        if j != i {
                            events.push(Event::Receive(j, message.clone()));
                        }
                    }
                }
                Event::Encrypt(i, ptxt, aad) => {
                    match agents
                        .get_mut(i as usize)
                        .unwrap()
                        .encrypt(ptxt.as_bytes().to_vec(), aad.as_bytes().to_vec())
                    {
                        Ok(ciphertext) => {
                            events.push(Event::Broadcast(i, ciphertext));
                        }
                        Err(e) => {
                            println!("**FAILED: {e}");
                        }
                    }
                }
                Event::Update(i) => match agents.get_mut(i as usize).unwrap().update() {
                    Ok(commit) => {
                        events.push(Event::Broadcast(i, commit));
                    }
                    Err(e) => {
                        println!("**FAILED: {e}");
                    }
                },
                Event::Add(i, key_package_message) => {
                    match agents.get_mut(i as usize).unwrap().add(key_package_message) {
                        Ok((commit, welcome)) => {
                            events.push(Event::Broadcast(i, commit));
                            events.push(Event::Broadcast(i, welcome));
                        }
                        Err(e) => {
                            println!("**FAILED: {e}");
                        }
                    }
                }
                Event::Receive(j, message) => {
                    // log
                    messages_received += 1;
                    bytes_received += message.mls_encoded_len();
                    // enqueue message for participant j
                    if let Some(dropped_message) =
                        agents.get_mut(j as usize).unwrap().enqueue(message)
                    {
                        // if a message was dropped, log it
                        println!("**DROPPED: {dropped_message:?}");
                    }
                    // push event for processing
                    events.push(Event::Process(j));
                }
                Event::Process(j) => match agents.get_mut(j as usize).unwrap().process() {
                    Ok(outcome) => match outcome {
                        // handle payload decryption
                        ProcessOutcome::PayloadDecrypted(group_id, epoch, ptxt, aad) => {
                            println!(
                            "DECRYPTED PAYLOAD in {}::{epoch}\nPLAINTEXT: {}\nAUTHENTICATED DATA: {}",
                            hex::encode(group_id),
                            String::from_utf8(ptxt).unwrap(),
                            String::from_utf8(aad).unwrap(),
                        );
                        }
                        // handle update
                        ProcessOutcome::UpdateApplied(group_id, epoch, commit) => {
                            println!(
                            "APPLIED COMMIT (EMPTY UPDATE) in {}::{epoch}\nCOMMIT TO BROADCAST: {commit:?}",
                            hex::encode(group_id)
                        );
                            // broadcast exporter-psk inject commit
                            events.push(Event::Broadcast(j, commit));
                        }
                        // handle other commit
                        ProcessOutcome::OtherCommitApplied(group_id, epoch) => {
                            println!(
                                "APPLIED COMMIT (NON-EMPTY) in {}::{epoch}",
                                hex::encode(group_id)
                            );
                        }
                        // handle group join
                        ProcessOutcome::GroupJoined(group_id, epoch) => {
                            println!("JOINED {}::{epoch}", hex::encode(group_id));
                        }
                        _ => {}
                    },
                    Err(e) => {
                        println!("**FAILED: {e}");
                    }
                },
            }
            event_counter += 1;
        }
    }
}
