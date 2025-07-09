#![doc = include_str!("../README.md")]
#![allow(
    clippy::multiple_crate_versions,
    clippy::large_enum_variant,
    clippy::result_large_err
)]

use mls_rs::{
    client_builder::{BaseConfig, WithCryptoProvider, WithIdentityProvider},
    error::MlsError,
    group::{CommitEffect, ContentType, ReceivedMessage},
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    mls_rules::{CommitOptions, DefaultMlsRules},
    psk::{ExternalPskId, PreSharedKey},
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, Group, MlsMessage,
    MlsMessageDescription, WireFormat,
};
use mls_rs_crypto_openssl::{OpensslCryptoError, OpensslCryptoProvider};
use std::{
    cmp::Ordering,
    collections::{HashMap, VecDeque},
};

/// A specialized message queue for prioritizing and ordering MLS messages.
///
/// `MlsMessageQueue` maintains two internal queues:
///
/// - `queue1`: A FIFO queue for control messages (e.g., Welcome, GroupInfo).
/// - `queue2`: A priority queue for application and commit messages, ordered by epoch.
///
/// This structure ensures that control messages are processed before application-layer
/// messages, and that application messages are processed in epoch order.
pub struct MlsMessageQueue {
    pub queue1: VecDeque<MlsMessage>,
    pub queue2: VecDeque<MlsMessage>,
    pub queue3: VecDeque<MlsMessage>,
}

impl Default for MlsMessageQueue {
    fn default() -> Self {
        Self::new(10000)
    }
}

impl MlsMessageQueue {
    /// Creates a new `MlsMessageQueue` instance with empty queues.
    pub fn new(capacity: usize) -> Self {
        Self {
            queue1: VecDeque::new(),
            queue2: VecDeque::with_capacity(capacity),
            queue3: VecDeque::new(),
        }
    }
    /// Dequeues the next `MlsMessage` from the queue.
    ///
    /// This method prioritizes control messages in `queue1`. If `queue1` is empty,
    /// it returns the next message from `queue2` (which is ordered by epoch).
    ///
    /// # Returns
    ///
    /// An `Option<MlsMessage>` containing the next message to process, or `None`
    /// if both queues are empty.
    pub fn dequeue(&mut self) -> Option<MlsMessage> {
        match self.queue1.pop_back() {
            Some(message) => Some(message),
            None => match self.queue2.pop_back() {
                Some(message) => Some(message),
                None => self.queue3.pop_back(),
            },
        }
    }
    /// Enqueues an `MlsMessage` into the appropriate internal queue.
    ///
    /// - Messages with `WireFormat::PublicMessage` or `WireFormat::PrivateMessage`
    ///   are inserted into `queue2` in ascending order of epoch.
    /// - All other messages are appended to `queue1` in FIFO order.
    ///
    /// # Arguments
    ///
    /// * `message` - The `MlsMessage` to enqueue.
    pub fn enqueue(&mut self, message: MlsMessage) -> Option<MlsMessage> {
        match message.wire_format() {
            WireFormat::PublicMessage | WireFormat::PrivateMessage => {
                let queue_len = self.queue2.len();
                let mut i = 0;
                // find the insertion point by wire format (protocol messages, and then welcome & other messages)
                // remember that the dequeue operation will remove from the END of the queue, so higher priority messages ned to go toward the END of the queue
                // get message description
                if let MlsMessageDescription::ProtocolMessage {
                    group_id: _,
                    epoch_id: message_epoch,
                    content_type: message_type,
                } = message.description()
                {
                    // find the last message in the same epoch
                    while i < queue_len && self.queue2[i].epoch().unwrap() > message_epoch {
                        i += 1;
                    }
                    // then, if the message is an application message, find the last application message in the same epoch
                    while i < queue_len
                        && self.queue2[i].epoch().unwrap() >= message_epoch
                        && message_type == ContentType::Commit
                    {
                        i += 1;
                    }
                    // now we have our insertion point
                    // now insert the message if we have the capacity
                    if queue_len == self.queue2.capacity() {
                        // queue is full, drop the oldest message
                        let dropped_message = self.queue2.pop_back().unwrap();
                        // insert new message
                        self.queue2.insert(i, message);
                        // return dropped message
                        Some(dropped_message)
                    } else {
                        // insert the message at the found index
                        self.queue2.insert(i, message);
                        // return None
                        None
                    }
                } else {
                    // if the message is not a protocol message, we cannot insert it into queue2
                    // so we just return None
                    None
                }
            }
            _ => {
                // just insert the message at the front of the vector
                self.queue1.push_front(message);
                None
            }
        }
    }
    /// Enqueues an `MlsMessage` that was previously dequeued.
    ///
    /// This method is used to re-enqueue messages that were deferred or need to be processed
    /// again after some condition has changed (e.g., a PSK became available).
    pub fn enqueue_again(&mut self, message: MlsMessage) {
        // re-enqueue the message in the same way as enqueue
        self.queue3.push_front(message);
    }
}

/// Represents errors that can occur during the operation of a `DistributedMlsAgent`.
///
/// This enum encapsulates both high-level protocol errors and low-level cryptographic
/// or library-specific issues. It is used throughout the library to provide meaningful
/// feedback and facilitate robust error handling.
///
/// # Variants
///
/// - `CipherSuiteNotAvailable`:  
///   The selected cipher suite is not supported by the configured crypto provider.
///
/// - `UnsupportedCipherSuite`:  
///   The cipher suite is unknown or lacks required metadata (e.g., hash length).
///
/// - `ExtraneousMlsMessage(MlsMessage)`:
///   The message is malformed or irrelevant to the agent's current state.
///
/// - `MlsMessageTooOld(MlsMessage)`:
///   The message is from a previous epoch and should be discarded.
///
/// - `UnauthorizedSender`:  
///   The message was sent by an unauthorized participant (e.g., not index 0).
///
/// - `MessageDeferred(MlsMessage)`:  
///   The message cannot be processed yet (e.g., due to missing PSKs or future epoch).
///
/// - `OpensslCryptoError(OpensslCryptoError)`:  
///   An error occurred in the underlying OpenSSL cryptographic provider.
///
/// - `MlsError(MlsError)`:  
///   An error occurred in the underlying MLS library.
///
/// - `IdentityNotFound`:  
///   The specified identity was not found in the send-group, e.g., when trying to
///   remove a participant that does not exist.
///
/// - `MessageQueueEmpty`:  
///   The message queue is empty, indicating no messages to process.
///
/// - `MessageQueueFull(MlsMessage)`:
///   The message queue is full, indicating that oldest messages will be dropped.
///
/// - `UnknownError(String)`:  
///   An unknown error occurred, typically due to a protocol violation or unexpected state.
#[derive(Debug)]
pub enum DistributedMlsError {
    /// Cipher suite not available with the given crypto provider.
    CipherSuiteNotAvailable,
    /// Unknown cipher suite; this error is thrown when we do not have information on a desired cipher suite, e.g., hash function output length
    UnsupportedCipherSuite,
    /// Message sender unauthorized, i.e., attempted to send a message in another participant's send-group.
    UnauthorizedSender,
    /// Message queue empty
    MessageQueueEmpty,
    /// Message queue full; oldest mesage dropped.
    MessageQueueFull(MlsMessage),
    /// Identity not found in the send-group, e.g., when trying to remove a participant that does not exist.
    IdentityNotFound,
    /// Message cannot be processed yet; may be processed later.
    MessageDeferred,
    /// Message cannot be processed yet due to missing PSK; may be processed later.
    MessageDeferredMissingPsk,
    /// Message cannot be processed at all and should be discarded.
    ExtraneousMlsMessage(MlsMessage),
    /// Message is from a previous epoch and should be discarded.
    MlsMessageTooOld(MlsMessage),
    /// Error from underlying OpenSSL library.
    OpensslCryptoError(OpensslCryptoError),
    /// Error from the MLS library.
    MlsError(MlsError),
    /// An unknown error occurred, typically due to a protocol violation or unexpected state.
    UnknownError(String),
}

impl core::fmt::Display for DistributedMlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Represents the outcome of processing an MLS message in a `DistributedMlsAgent`.
///
/// This enum captures the various results of processing messages, including successful
/// decryption of payloads, application of updates, joining groups, and other outcomes.
///
/// # Variants
///
/// - `PayloadDecrypted(Vec<u8>, u64, Vec<u8>, Vec<u8>)`:  
///   Indicates a successful decryption of an application message payload.
///   Contains the group ID, epoch, decrypted payload, and authenticated data.
///
/// - `UpdateApplied(Vec<u8>, u64, MlsMessage)`:  
///   Indicates a successful application of an update to the send-group.
///   Contains the group ID, epoch, and the commit message generated by the update.
///
/// - `OtherCommitApplied(Vec<u8>, u64)`:  
///   Indicates a commit message was applied to a receive-group that did not result in a PSK update.
///   Contains the group ID and epoch of the commit.
///
/// - `GroupJoined(Vec<u8>, u64)`:  
///   Indicates the agent successfully joined a new group.
///   Contains the group ID and epoch of the new group.
///
/// - `Nothing`:  
///   Indicates that no action was taken during processing, e.g., no messages to process or
///   no relevant updates to apply.
#[derive(Debug)]
pub enum ProcessOutcome {
    /// Represents the outcome of processing an MLS message.
    PayloadDecrypted(Vec<u8>, u64, Vec<u8>, Vec<u8>),
    /// Represents the outcome of applying an empty update, which should result in an ExporterPSK inject.
    UpdateApplied(Vec<u8>, u64, MlsMessage),
    /// Represents the outcome of applying a commit message to a receive-group that did not result in an ExporterPSK inject.
    OtherCommitApplied(Vec<u8>, u64),
    /// Represents the outcome of successfully joining a new group.
    GroupJoined(Vec<u8>, u64),
    /// Represents a no-op outcome, i.e., nothing to process or apply.
    Nothing,
}

type DistributedMlsConfig = WithIdentityProvider<
    BasicIdentityProvider,
    WithCryptoProvider<OpensslCryptoProvider, BaseConfig>,
>;

/// A high-level agent for managing secure group communication using Distributed MLS (DMLS).
///
/// `DistributedMlsAgent` encapsulates the logic for creating, joining, and maintaining
/// multiple MLS groups in a distributed setting. Each agent manages:
///
/// - A **send-group**, which it creates and controls.
/// - Multiple **receive-groups**, which it joins based on welcome messages from peers.
///
/// The agent supports secure message encryption, decryption, group updates, and
/// post-compromise security (PCS) healing using pre-shared keys (PSKs).
///
/// ### Key Features
///
/// - Initializes and manages MLS groups using the `mls-rs` library.
/// - Handles MLS message processing, including application and commit messages.
/// - Supports PCS healing via exporter-derived PSKs.
/// - Maintains internal state transitions (`Uninitialized`, `Initializing`, `Initialized`)
///   to ensure correct protocol behavior.
///
/// ### Usage
///
/// 1. Create an agent with `new`.
/// 2. Generate a key package with `generate_key_package_message`.
/// 3. Initialize the send-group with peers using `initialize`.
/// 4. Process incoming messages with `process`.
/// 5. Encrypt messages with `encrypt`.
/// 6. Periodically call `update` to maintain PCS.
///
/// This struct is intended for use in decentralized or federated messaging systems
/// where each participant manages their own MLS group and joins others' groups
/// to form a mesh of secure communication channels.
pub struct DistributedMlsAgent {
    pub queue: MlsMessageQueue,
    pub client: Client<DistributedMlsConfig>,
    pub send_group: Group<DistributedMlsConfig>,
    pub recv_groups: HashMap<Vec<u8>, Group<DistributedMlsConfig>>,
    pub exporter_length: usize,
}

impl DistributedMlsAgent {
    /// Creates a new `DistributedMlsAgent` instance with the given identifier.
    ///
    /// This function initializes the MLS client with a predefined cipher suite
    /// (`CURVE25519_AES128`) and sets up the cryptographic and identity providers.
    /// It generates a fresh signature key pair and configures the client with
    /// default MLS rules that require path-based commits.
    ///
    /// # Arguments
    ///
    /// * `name` - A byte vector representing the identifier of the agent.
    ///
    /// # Returns
    ///
    /// A `Result` containing the initialized `DistributedMlsAgent` on success,
    /// or a `DistributedMlsError` if the cipher suite is unavailable or key generation fails.
    pub fn new(name: Vec<u8>, exporter_length: usize) -> Result<Self, DistributedMlsError> {
        // cipher suite choice
        let cipher_suite_choice = CipherSuite::CURVE25519_AES128;
        // openssl crypto provider
        let crypto_provider = OpensslCryptoProvider::default();
        // cipher suite selection
        let cipher_suite = crypto_provider
            .cipher_suite_provider(cipher_suite_choice)
            .map_or_else(|| Err(DistributedMlsError::CipherSuiteNotAvailable), Ok)?;
        // signature key gen
        let (secret, public) = cipher_suite
            .signature_key_generate()
            .map_err(DistributedMlsError::OpensslCryptoError)?;
        // client
        let client = Client::builder()
            .identity_provider(BasicIdentityProvider)
            .crypto_provider(crypto_provider)
            .mls_rules(
                DefaultMlsRules::new()
                    .with_commit_options(CommitOptions::new().with_path_required(true)),
            )
            .signing_identity(
                SigningIdentity::new(BasicCredential::new(name).into_credential(), public),
                secret,
                cipher_suite_choice,
            )
            .build();
        // send group
        let send_group = client
            .create_group(ExtensionList::default(), Default::default(), None)
            .map_err(DistributedMlsError::MlsError)?;
        // done; the rest of the variables are given initial values
        Ok(Self {
            client,
            send_group,
            recv_groups: HashMap::new(),
            queue: Default::default(),
            exporter_length,
        })
    }
    /// Generates a new MLS key package message for this agent.
    ///
    /// This key package can be shared with other participants to allow them to
    /// add this agent to their MLS groups. It includes the agent's public key and
    /// supported extensions.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `MlsMessage` representing the key package,
    /// or a `DistributedMlsError` if generation fails.
    pub fn generate_key_package_message(&self) -> Result<MlsMessage, DistributedMlsError> {
        self.client
            .generate_key_package_message(ExtensionList::default(), ExtensionList::default(), None)
            .map_err(DistributedMlsError::MlsError)
    }
    /// Performs a self-update and initiates PCS (Post-Compromise Security) healing.
    ///
    /// This method commits a self-update to the send-group, derives a new
    /// pre-shared key (PSK) using the MLS exporter, and stores it in the client's
    /// secret store. This PSK can later be used to heal other groups via external PSK commits.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `MlsMessage` representing the commit message,
    /// or a `DistributedMlsError` if the group is uninitialized or the update fails.
    pub fn update(&mut self) -> Result<MlsMessage, DistributedMlsError> {
        // commit update in send group immediately
        let commit_message = self
            .send_group
            .commit_builder()
            .build()
            .map_err(DistributedMlsError::MlsError)?
            .commit_message;
        self.send_group
            .apply_pending_commit()
            .map_err(DistributedMlsError::MlsError)?;
        // generate psk_id as context for exporter
        let mut psk_id_vec = Vec::from(self.send_group.current_epoch().to_be_bytes());
        psk_id_vec.extend(self.send_group.group_id().to_vec());
        // export secret
        let exporter = self
            .send_group
            .export_secret(b"exporter_psk", psk_id_vec.as_slice(), self.exporter_length)
            .map_err(DistributedMlsError::MlsError)?;
        // store as psk
        self.client.secret_store().insert(
            ExternalPskId::new(psk_id_vec),
            PreSharedKey::new(exporter.to_vec()),
        );
        // done
        Ok(commit_message)
    }
    /// Adds a new participant to the agent's send-group.
    ///
    /// This method processes a key package message from another participant,
    /// committing it to the send-group and generating a welcome message for that participant.
    pub fn add(
        &mut self,
        key_package_message: MlsMessage,
    ) -> Result<(MlsMessage, MlsMessage), DistributedMlsError> {
        // add participants to send-group
        let mut commit = self
            .send_group
            .commit_builder()
            .add_member(key_package_message)
            .map_err(DistributedMlsError::MlsError)?
            .build()
            .map_err(DistributedMlsError::MlsError)?;
        self.send_group
            .apply_pending_commit()
            .map_err(DistributedMlsError::MlsError)?;
        // output welcome(s)
        Ok((commit.commit_message, commit.welcome_messages.remove(0)))
    }
    /// Removes a participant from the agent's send-group.
    ///
    /// This method finds the member by their identity, commits the removal,
    /// and returns the resulting commit message.
    ///
    /// # Arguments
    ///
    /// * `identity` - A byte vector representing the identity of the participant to remove.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `MlsMessage` representing the commit message,
    /// or a `DistributedMlsError` if the member is not found or the removal fails.
    pub fn remove(&mut self, identity: Vec<u8>) -> Result<MlsMessage, DistributedMlsError> {
        // find member in send group
        let member = self
            .send_group
            .member_with_identity(identity.as_slice())
            .map_err(DistributedMlsError::MlsError)?;
        // remove member from send-group
        let commit = self
            .send_group
            .commit_builder()
            .remove_member(member.index)
            .map_err(DistributedMlsError::MlsError)?
            .build()
            .map_err(DistributedMlsError::MlsError)?;
        self.send_group
            .apply_pending_commit()
            .map_err(DistributedMlsError::MlsError)?;
        // output commit message
        Ok(commit.commit_message)
    }
    /// Encrypts an application message using the agent's send-group.
    ///
    /// This method wraps the provided plaintext in an MLS application message
    /// and encrypts it using the current state of the send-group.
    ///
    /// # Arguments
    ///
    /// * `ptxt` - A byte slice representing the plaintext to encrypt.
    /// * `ad` - A byte slice representing additional authenticated data (AAD) to be sent
    ///
    /// # Returns
    ///
    /// A `Result` containing the encrypted `MlsMessage`, or a `DistributedMlsError`
    /// if the group is uninitialized or encryption fails.
    pub fn encrypt(
        &mut self,
        ptxt: Vec<u8>,
        ad: Vec<u8>,
    ) -> Result<MlsMessage, DistributedMlsError> {
        self.send_group
            .encrypt_application_message(ptxt.as_slice(), ad)
            .map_err(DistributedMlsError::MlsError)
    }
    /// Enqueues an incoming MLS message for future processing.
    ///
    /// This method is used to initially handle messages received from other participants.
    /// It adds the message to the agent's internal queue for processing in the
    /// correct order, ensuring that messages are processed according to ordering requirements for MLS.
    pub fn enqueue(&mut self, message: MlsMessage) -> Option<MlsMessage> {
        self.queue.enqueue(message)
    }
    /// Re-enqueues an `MlsMessage` that was previously dequeued.
    ///
    /// This method is used to re-enqueue messages that were deferred or need to be processed
    /// again after some condition has changed (e.g., a PSK became available).
    pub fn enqueue_again(&mut self, message: MlsMessage) {
        self.queue.enqueue_again(message)
    }
    /// Processes an incoming MLS message and updates internal state accordingly.
    ///
    /// # Returns
    ///
    /// A `Result` containing a tuple:
    /// - An optional`MlsMessage` to be sent in response (e.g., commit message).
    /// - An optional decrypted application message payload, if applicable.
    ///
    /// Returns a `DistributedMlsError` if the message is invalid, from an unknown group,
    /// unauthorized, outdated, or cannot yet be processed.
    pub fn process(&mut self) -> Result<ProcessOutcome, DistributedMlsError> {
        match self.queue.dequeue() {
            Some(message) => {
                match message.wire_format() {
                    WireFormat::Welcome => {
                        // try to join group
                        let (new_group, _info) = self
                            .client
                            .join_group(None, &message, None)
                            .map_err(DistributedMlsError::MlsError)?;
                        let new_group_id = new_group.group_id().to_vec();
                        let new_group_epoch = new_group.current_epoch();
                        // add to recv-groups
                        self.recv_groups.insert(new_group_id.clone(), new_group);
                        // done
                        Ok(ProcessOutcome::GroupJoined(new_group_id, new_group_epoch))
                    }
                    WireFormat::PublicMessage | WireFormat::PrivateMessage => {
                        match message.description() {
                            MlsMessageDescription::ProtocolMessage {
                                group_id: message_group_id,
                                epoch_id: message_epoch,
                                content_type: message_type,
                            } => {
                                match self.recv_groups.get_mut(message_group_id) {
                                    Some(recv_group) => {
                                        match message_epoch.cmp(&recv_group.current_epoch()) {
                                            Ordering::Equal => match message_type {
                                                ContentType::Application => {
                                                    match recv_group
                                                        .process_incoming_message(message)
                                                        .map_err(DistributedMlsError::MlsError)?
                                                    {
                                                        ReceivedMessage::ApplicationMessage(
                                                            decrypted_appmsg,
                                                        ) => {
                                                            if decrypted_appmsg.sender_index == 0 {
                                                                Ok(ProcessOutcome::PayloadDecrypted(
                                                                    recv_group.group_id().to_vec(),
                                                                    recv_group.current_epoch(),
                                                                    decrypted_appmsg.data().to_vec(),
                                                                    decrypted_appmsg
                                                                        .authenticated_data
                                                                        .clone(),
                                                                ))
                                                            } else {
                                                                Err(DistributedMlsError::UnauthorizedSender)
                                                            }
                                                        }
                                                        _ => Err(DistributedMlsError::UnknownError(
                                                            "Received non-application message with ContentType::Application".to_string(),
                                                        )),
                                                    }
                                                }
                                                ContentType::Commit => {
                                                    let mut recv_group_clone = recv_group.clone();
                                                    let message_clone = message.clone();
                                                    match recv_group_clone
                                                        .process_incoming_message(message_clone)                                                     {
                                                        Ok(received_message) => match received_message {
                                                            ReceivedMessage::Commit(decrypted_commit) => {
                                                                if decrypted_commit.committer == 0 {
                                                                    *recv_group = recv_group_clone;
                                                                    match decrypted_commit.effect {
                                                                        CommitEffect::NewEpoch(new_epoch) => {
                                                                            if new_epoch.applied_proposals.is_empty() {
                                                                                // generate psk_id as context for exporter
                                                                                let mut psk_id_vec = Vec::from(
                                                                                    recv_group
                                                                                        .current_epoch()
                                                                                        .to_be_bytes(),
                                                                                );
                                                                                psk_id_vec
                                                                                    .extend(recv_group.group_id().to_vec());
                                                                                // export secret
                                                                                let exporter = recv_group
                                                                                    .export_secret(
                                                                                        b"exporter_psk",
                                                                                        psk_id_vec.as_slice(),
                                                                                        self.exporter_length,
                                                                                    )
                                                                                    .map_err(
                                                                                        DistributedMlsError::MlsError,
                                                                                    )?;
                                                                                // store as psk
                                                                                self.client.secret_store().insert(
                                                                                    ExternalPskId::new(psk_id_vec.clone()),
                                                                                    PreSharedKey::new(exporter.to_vec()),
                                                                                );
                                                                                // commit the psk in send-group
                                                                                let commit_message = self.send_group
                                                                                    .commit_builder()
                                                                                    .add_external_psk(ExternalPskId::new(
                                                                                        psk_id_vec.clone(),
                                                                                    ))
                                                                                    .map_err(DistributedMlsError::MlsError)?
                                                                                    .build()
                                                                                    .map_err(DistributedMlsError::MlsError)?
                                                                                    .commit_message;
                                                                                self.send_group.apply_pending_commit().map_err(
                                                                                    DistributedMlsError::MlsError,
                                                                                )?;
                                                                                Ok(ProcessOutcome::UpdateApplied(
                                                                                    recv_group.group_id().to_vec(),
                                                                                    recv_group.current_epoch() - 1,
                                                                                    commit_message,
                                                                                ))
                                                                            } else {
                                                                                // no psk to commit, just return None
                                                                                Ok(ProcessOutcome::OtherCommitApplied(
                                                                                    recv_group.group_id().to_vec(),
                                                                                    recv_group.current_epoch() - 1,
                                                                                ))
                                                                            }
                                                                        }
                                                                        _ => Ok(ProcessOutcome::OtherCommitApplied(recv_group.group_id().to_vec(), recv_group.current_epoch() - 1)),
                                                                    }
                                                                } else {
                                                                    Err(DistributedMlsError::UnauthorizedSender)
                                                                }
                                                            }
                                                            _ => Err(DistributedMlsError::UnknownError(
                                                                "Received non-commit message with ContentType::Commit".to_string(),
                                                            )),
                                                        }
                                                        Err(MlsError::MissingRequiredPsk) => {
                                                            self.queue.enqueue_again(message);
                                                            Err(DistributedMlsError::MessageDeferredMissingPsk)
                                                        }
                                                        Err(e) => Err(DistributedMlsError::MlsError(e)),
                                                    }
                                                }
                                                _ => {
                                                    Err(DistributedMlsError::ExtraneousMlsMessage(
                                                        message,
                                                    ))
                                                }
                                            },
                                            Ordering::Less => {
                                                Err(DistributedMlsError::MlsMessageTooOld(message))
                                            }
                                            Ordering::Greater => {
                                                self.queue.enqueue_again(message);
                                                Err(DistributedMlsError::MessageDeferred)
                                            }
                                        }
                                    }
                                    None => {
                                        self.queue.enqueue_again(message);
                                        Err(DistributedMlsError::MessageDeferred)
                                    }
                                }
                            }
                            _ => Err(DistributedMlsError::UnknownError(
                                "Received non-protocol message with PublicMessage or PrivateMessage wire format".to_string(),
                            )),
                        }
                    }
                    _ => Err(DistributedMlsError::ExtraneousMlsMessage(message)),
                }
            }
            None => Err(DistributedMlsError::MessageQueueEmpty),
        }
    }
}
