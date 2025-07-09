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
use std::collections::{HashMap, VecDeque};

use md5 as _;
use mls_rs_crypto_openssl as _;

#[derive(Debug)]
enum Event {
    Broadcast(usize, MlsMessage),
    Receive(usize, usize),
    Encrypt(usize, String, String),
    Process(usize),
    Add(usize, MlsMessage),
    Update(usize),
}

/// struct for command-line arguments
#[derive(clap::Parser, Debug)]
struct CliArgStruct {
    /// number of participants
    #[arg(short, long, default_value_t = 3)]
    num_participants: usize,
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
    // message queues
    let mut message_queues: HashMap<(usize, usize), VecDeque<MlsMessage>> = HashMap::new();
    // participants
    let mut agents = Vec::new();
    // counters
    let mut event_counter = 0;
    // create participants
    for i in 0..args.num_participants {
        eprintln!("\nCREATING PARTICIPANT {i}");
        match DistributedMlsAgent::new(i.to_be_bytes().to_vec(), args.exporter_length) {
            Ok(agent) => {
                agents.push(agent);
            }
            Err(e) => {
                eprintln!("**FAILED: {e}");
            }
        }
        // initialize message queues
        for j in 0..args.num_participants {
            if j != i {
                message_queues.insert((i, j), VecDeque::new());
            }
        }
    }
    // seed initialization events & run in phases
    for phase in 0..3 {
        eprintln!("\n=== PHASE {phase} ===");
        // seed events by phase
        match phase {
            0 => {
                // phase 0: everyone adds everyone else
                for i in 0..agents.len() {
                    for j in 0..agents.len() {
                        if j != i {
                            eprintln!("\nSEEDING EVENT: PARTICIPANT {i} ADDS {j}");
                            match agents.get(j).unwrap().generate_key_package_message() {
                                Ok(key_package_message) => {
                                    // push add event
                                    events.push(Event::Add(i, key_package_message));
                                }
                                Err(e) => {
                                    eprintln!("**FAILED: {e}");
                                }
                            }
                        }
                    }
                }
            }
            1 => {
                // phase 1: everyone updates and broadcasts a message
                for i in 0..agents.len() {
                    eprintln!("\nSEEDING EVENT: PARTICIPANT {i} ENCRYPTS MESSAGE");
                    events.push(Event::Encrypt(
                        i,
                        format!("Hello, world, from participant {i}!"),
                        format!("Test AAD!"),
                    ));
                }
            }
            2 => {
                // phase 2: everyone updates and broadcasts a message
                for i in 0..agents.len() {
                    eprintln!("\nSEEDING EVENT: PARTICIPANT {i} UPDATES");
                    events.push(Event::Update(i));
                }
            }
            _ => {}
        }
        // run the current phase of simulation
        while !events.is_empty() {
            // pull next event; this is a uniform random selection
            let event = events.remove(rng.next_u64() as usize % events.len());
            event_counter += 1;
            // log
            eprintln!("\nHANDLING EVENT: {event:?}");
            // handle event
            match event {
                Event::Broadcast(i, message) => {
                    // log
                    println!(
                        "{event_counter},{i},broadcast,{}",
                        message.mls_encoded_len()
                    );
                    // broadcast message to all participants
                    for j in 0..agents.len() {
                        if j != i {
                            // add to message queue
                            message_queues
                                .get_mut(&(i, j))
                                .unwrap()
                                .push_back(message.clone());
                            events.push(Event::Receive(j, i));
                        }
                    }
                }
                Event::Encrypt(i, ptxt, aad) => {
                    match agents
                        .get_mut(i)
                        .unwrap()
                        .encrypt(ptxt.as_bytes().to_vec(), aad.as_bytes().to_vec())
                    {
                        Ok(ciphertext) => {
                            // log
                            println!(
                                "{event_counter},{i},encrypt,{},{},success,{}",
                                ptxt.len(),
                                aad.len(),
                                ciphertext.mls_encoded_len()
                            );
                            // push broadcast event
                            events.push(Event::Broadcast(i, ciphertext));
                        }
                        Err(e) => {
                            eprintln!("**FAILED: {e}");
                            // log
                            println!(
                                "{event_counter},{i},encrypt,{},{},fail",
                                ptxt.len(),
                                aad.len()
                            );
                        }
                    }
                }
                Event::Update(i) => match agents.get_mut(i).unwrap().update() {
                    Ok(commit) => {
                        // log
                        println!(
                            "{event_counter},{i},update,success,{}",
                            commit.mls_encoded_len()
                        );
                        // push broadcast event
                        events.push(Event::Broadcast(i, commit));
                    }
                    Err(e) => {
                        eprintln!("**FAILED: {e}");
                        // log
                        println!("{event_counter},{i},update,fail");
                    }
                },
                Event::Add(i, key_package_message) => {
                    match agents.get_mut(i).unwrap().add(key_package_message) {
                        Ok((commit, welcome)) => {
                            // log
                            println!(
                                "{event_counter},{i},add,success,{},{}",
                                commit.mls_encoded_len(),
                                welcome.mls_encoded_len()
                            );
                            // push events
                            events.push(Event::Broadcast(i, commit));
                            events.push(Event::Broadcast(i, welcome));
                        }
                        Err(e) => {
                            eprintln!("**FAILED: {e}");
                            println!("{event_counter},{i},add,fail");
                        }
                    }
                }
                Event::Receive(i, j) => {
                    // get message from message queue
                    let message = message_queues
                        .get_mut(&(j, i))
                        .unwrap()
                        .pop_front()
                        .unwrap();
                    // log
                    println!(
                        "{event_counter},{i},receive,{j},{}",
                        message.mls_encoded_len()
                    );
                    // enqueue message for participant j
                    if let Some(dropped_message) = agents.get_mut(i).unwrap().enqueue(message) {
                        // if a message was dropped, log it
                        eprintln!("**DROPPED: {dropped_message:?}");
                    }
                    // push event for processing
                    events.push(Event::Process(i));
                }
                Event::Process(i) => match agents.get_mut(i).unwrap().process() {
                    Ok(outcome) => match outcome {
                        // handle payload decryption
                        ProcessOutcome::PayloadDecrypted(group_id, epoch, ptxt, aad) => {
                            println!(
                                "{event_counter},{i},process,payload_decrypted,{},{}",
                                ptxt.len(),
                                aad.len()
                            );
                            eprintln!(
                            "DECRYPTED PAYLOAD in {}::{epoch}\nPLAINTEXT: {}\nAUTHENTICATED DATA: {}",
                            hex::encode(group_id),
                            String::from_utf8(ptxt).unwrap(),
                            String::from_utf8(aad).unwrap(),
                        );
                        }
                        // handle update
                        ProcessOutcome::UpdateApplied(group_id, epoch, commit) => {
                            println!(
                                "{event_counter},{i},process,update_applied,{}",
                                commit.mls_encoded_len()
                            );
                            eprintln!(
                            "APPLIED COMMIT (EMPTY UPDATE) in {}::{epoch}\nCOMMIT TO BROADCAST: {commit:?}",
                            hex::encode(group_id)
                        );
                            // broadcast exporter-psk inject commit
                            events.push(Event::Broadcast(i, commit));
                        }
                        // handle other commit
                        ProcessOutcome::OtherCommitApplied(group_id, epoch) => {
                            println!(
                                "{event_counter},{i},process,other_commit_applied"
                            );
                            eprintln!(
                                "APPLIED COMMIT (NON-EMPTY) in {}::{epoch}",
                                hex::encode(group_id)
                            );
                        }
                        // handle group join
                        ProcessOutcome::GroupJoined(group_id, epoch) => {
                            println!(
                                "{event_counter},{i},process,joined"
                            );
                            eprintln!("JOINED {}::{epoch}", hex::encode(group_id));
                        }
                        _ => {}
                    },
                    Err(DistributedMlsError::MessageDeferred) => {
                        println!(
                                "{event_counter},{i},process,deferred"
                            );
                        eprintln!("**DEFERRED");
                    }
                    Err(DistributedMlsError::MessageDeferredMissingPsk) => {
                        println!(
                                "{event_counter},{i},process,deferred_psk"
                            );
                        eprintln!("**DEFERRED DUE TO MISSING PSK");
                    }
                    Err(e) => {
                        eprintln!("**FAILED: {e}");
                    }
                },
            }
        }
    }
}
