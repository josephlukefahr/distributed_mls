High-level Rust library for secure, decentralized group communication
built on top of the Messaging Layer Security (MLS) protocol.

It wraps the `mls-rs` and `mls-rs-crypto-openssl`
crates to provide a structured API for managing MLS groups in distributed systems.

## Features

- **Send/Receive Group Model**: Each agent manages its own send-group and joins others' receive-groups.
- **Secure Message Exchange**: Encrypt and decrypt MLS application messages.
- **Post-Compromise Security (PCS)**: Heal groups using exporter-derived pre-shared keys (PSKs).
- **Stateful Protocol Management**: Tracks lifecycle through `Uninitialized`, `Initializing`, and `Initialized` states.
- **Robust Error Handling**: Rich error types for precise diagnostics.

## Example

```rust
use distributed_mls::DistributedMlsAgent;

// participants
let mut alice = DistributedMlsAgent::new(b"alice".to_vec()).unwrap();
let mut bob = DistributedMlsAgent::new(b"bob".to_vec()).unwrap();
let mut charlie = DistributedMlsAgent::new(b"charlie".to_vec()).unwrap();

// initialize group
let alice_messages = alice
    .initialize(vec![
        bob.generate_key_package_message().unwrap(),
        charlie.generate_key_package_message().unwrap(),
    ])
    .unwrap();
let bob_messages = bob
    .initialize(vec![
        alice.generate_key_package_message().unwrap(),
        charlie.generate_key_package_message().unwrap(),
    ])
    .unwrap();
let charlie_messages = charlie
    .initialize(vec![
        alice.generate_key_package_message().unwrap(),
        bob.generate_key_package_message().unwrap(),
    ])
    .unwrap();

// process incoming welcome messages
for alice_message in alice_messages {
    bob.process(alice_message.clone()).unwrap();
    charlie.process(alice_message.clone()).unwrap();
}
for bob_message in bob_messages {
    alice.process(bob_message.clone()).unwrap();
    charlie.process(bob_message.clone()).unwrap();
}
for charlie_message in charlie_messages {
    alice.process(charlie_message.clone()).unwrap();
    bob.process(charlie_message.clone()).unwrap();
}

// send a message from alice
let alice_message = alice.encrypt(&[0]).unwrap();

// process incoming messages from alice
let (_, _bob_ptxt_opt) = bob.process(alice_message.clone()).unwrap();
let (_, _charlie_ptxt_opt) = charlie.process(alice_message.clone()).unwrap();
```

## Use Cases

- Secure group messaging in federated or peer-to-peer systems
- Distributed consensus protocols
- IoT networks with decentralized trust

## License

Licensed under either the MIT or Apache-2.0 license.
