High-level Rust library for secure, decentralized group communication
built on top of the Messaging Layer Security (MLS) protocol.

It wraps the `mls-rs` and `mls-rs-crypto-openssl`
crates to provide a structured API for managing MLS groups in distributed systems.

## Features

- **Message Queuing**: Prioritized, epoch-ordered message queue for MLS messages.
- **Send/Receive Group Model**: Each agent manages its own send-group and joins others' receive-groups.
- **Secure Message Exchange**: Encrypt and decrypt MLS application messages.
- **Post-Compromise Security (PCS)**: Heal groups using exporter-derived pre-shared keys (PSKs).
- **Stateful Protocol Management**: Tracks lifecycle through `Uninitialized`, `Initializing`, and `Initialized` states.
- **Robust Error Handling**: Rich error types for precise diagnostics.

## Message Queuing: `MlsMessageQueue`

The `MlsMessageQueue` is a specialized queue for handling MLS messages with correct prioritization and ordering. It is designed to ensure that control messages (such as Welcome or GroupInfo) are processed before application-layer messages, and that application messages are processed in epoch order.

### How It Works

- **Two Internal Queues**:
  - `queue1`: FIFO queue for control messages (e.g., Welcome, GroupInfo).
  - `queue2`: Priority queue for application and commit messages, ordered by epoch.

- **Enqueueing**:
  - Messages with `WireFormat::PublicMessage` or `WireFormat::PrivateMessage` are inserted into `queue2` in ascending order of epoch.
  - All other messages are appended to `queue1` in FIFO order.

- **Dequeuing**:
  - Control messages in `queue1` are always dequeued first.
  - If `queue1` is empty, the next message from `queue2` (lowest epoch) is dequeued.

## DistributedMlsAgent

The `DistributedMlsAgent` is the main abstraction for managing secure group communication in a distributed setting. Each agent manages its own **send-group** (which it creates and controls) and joins other participants' **receive-groups** (by processing welcome messages from peers). This enables a mesh of secure channels between all participants.

### Lifecycle

- **Uninitialized**: The agent is created but has not yet initialized its own send-group.
- **Initializing**: The agent has created its send-group and is waiting to join other participants' send-groups.
- **Initialized**: The agent has joined all expected receive-groups and is fully operational.

### Key Operations

- **Key Package Generation**:  
  Each agent generates a key package that it shares with peers so they can add it to their groups.

- **Group Initialization**:  
  The agent creates its own send-group and initializes it with the key packages of all participants (including itself). This produces welcome messages for peers.

- **Processing Messages**:  
  The agent processes incoming messages (welcome, application, commit, etc.) using the `process` method. This updates group state and delivers plaintext messages as appropriate.

- **Encrypting Messages**:  
  The agent can encrypt application messages for the group using the `encrypt` method.

- **Post-Compromise Security (PCS)**:  
  The agent can periodically update its group using exporter-derived pre-shared keys to heal from compromise.

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

Licensed under either the MIT license.
