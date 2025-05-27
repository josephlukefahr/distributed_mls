//! Basic example of DMLS usage.

use clap as _;
use mls_rs as _;
use mls_rs_crypto_openssl as _;
use rand_chacha as _;

use distributed_mls::{DistributedMlsAgent, DistributedMlsError};

fn main() {
    println!("=== BASIC EXAMPLE ===");
    // participants
    let mut alice = DistributedMlsAgent::new(b"alice".to_vec()).unwrap();
    println!("( 1) created alice");
    let mut bob = DistributedMlsAgent::new(b"bob".to_vec()).unwrap();
    println!("( 2) created bob");
    let mut charlie = DistributedMlsAgent::new(b"charlie".to_vec()).unwrap();
    println!("( 3) created charlie");
    // initialize group
    let alice_messages = alice
        .initialize(vec![
            bob.generate_key_package_message().unwrap(),
            charlie.generate_key_package_message().unwrap(),
        ])
        .unwrap();
    println!("( 4) alice initialized her dmls send-group with [bob, charlie]");
    let bob_messages = bob
        .initialize(vec![
            alice.generate_key_package_message().unwrap(),
            charlie.generate_key_package_message().unwrap(),
        ])
        .unwrap();
    println!("( 5) bob initialized his dmls send-group with [alice, charlie]");
    let charlie_messages = charlie
        .initialize(vec![
            alice.generate_key_package_message().unwrap(),
            bob.generate_key_package_message().unwrap(),
        ])
        .unwrap();
    println!("( 6) charlie initialized his dmls send-group with [alice, bob]");
    for alice_message in alice_messages {
        bob.process(alice_message.clone()).unwrap();
        charlie.process(alice_message.clone()).unwrap();
    }
    println!("( 7) bob & charlie joined alice's send-group");
    for bob_message in bob_messages {
        alice.process(bob_message.clone()).unwrap();
        charlie.process(bob_message.clone()).unwrap();
    }
    println!("( 8) alice & charlie joined bob's send-group");
    for charlie_message in charlie_messages {
        alice.process(charlie_message.clone()).unwrap();
        bob.process(charlie_message.clone()).unwrap();
    }
    println!("( 9) alice & bob joined charlie's send-group");
    // send a message from alice
    let alice_ptxt = &[0];
    let alice_message = alice.encrypt(alice_ptxt).unwrap();
    println!("(10) alice sent {alice_ptxt:?}");
    let (_, bob_ptxt_opt) = bob.process(alice_message.clone()).unwrap();
    if let Some(bob_ptxt) = bob_ptxt_opt {
        println!("(11) bob received {bob_ptxt:?}");
    }
    let (_, charlie_ptxt_opt) = charlie.process(alice_message.clone()).unwrap();
    if let Some(charlie_ptxt) = charlie_ptxt_opt {
        println!("(12) charlie received {charlie_ptxt:?}");
    }
    // update bob
    let bob_commit = bob.update().unwrap();
    println!("(13) bob updated");
    let (alice_commits, _) = alice.process(bob_commit.clone()).unwrap();
    println!("(14) alice processed bob's commit");
    for alice_commit in &alice_commits {
        bob.process(alice_commit.clone()).unwrap();
        if let Err(DistributedMlsError::MessageDeferred(_)) = charlie.process(alice_commit.clone())
        {
            println!("(15c) charlie deferred alice's exporter-psk because he has not yet processed bob's update!");
        }
    }
    println!("(15b) bob processed alice's exporter-psk from bob's update");
    let (charlie_commits, _) = charlie.process(bob_commit.clone()).unwrap();
    println!("(16) charlie processed bob's commit");
    for charlie_commit in &charlie_commits {
        alice.process(charlie_commit.clone()).unwrap();
        bob.process(charlie_commit.clone()).unwrap();
    }
    println!("(17) alice & bob processed charlie's exporter-psk from bob's update");
    for alice_commit in &alice_commits {
        charlie.process(alice_commit.clone()).unwrap();
    }
    println!("(15c) charlie re-processed alice's exporter-psk from bob's update");
    // send a message from bob
    let bob_ptxt = &[2];
    let bob_message = bob.encrypt(bob_ptxt).unwrap();
    println!("(18) bob sent {bob_ptxt:?}");
    let (_, alice_ptxt_opt) = alice.process(bob_message.clone()).unwrap();
    if let Some(alice_ptxt) = alice_ptxt_opt {
        println!("(19) alice received {alice_ptxt:?}");
    }
    let (_, charlie_ptxt_opt) = charlie.process(bob_message.clone()).unwrap();
    if let Some(charlie_ptxt) = charlie_ptxt_opt {
        println!("(20) charlie received {charlie_ptxt:?}");
    }
    // send a message from charlie
    let charlie_ptxt = &[1];
    let charlie_message = charlie.encrypt(charlie_ptxt).unwrap();
    println!("(21) charlie sent {charlie_ptxt:?}");
    let (_, alice_ptxt_opt) = alice.process(charlie_message.clone()).unwrap();
    if let Some(alice_ptxt) = alice_ptxt_opt {
        println!("(22) alice received {alice_ptxt:?}");
    }
    let (_, bob_ptxt_opt) = bob.process(charlie_message.clone()).unwrap();
    if let Some(bob_ptxt) = bob_ptxt_opt {
        println!("(23) bob received {bob_ptxt:?}");
    }
    // done
    println!("=== DONE WITH BASIC EXAMPLE ===");
}
