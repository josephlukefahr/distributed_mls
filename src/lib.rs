#![doc = include_str!("../README.md")]
#![allow(
    clippy::multiple_crate_versions,
    clippy::large_enum_variant,
    clippy::result_large_err
)]

use mls_rs::{
    client_builder::{BaseConfig, WithCryptoProvider, WithIdentityProvider},
    error::MlsError,
    group::{CommitEffect, ReceivedMessage},
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    mls_rules::{CommitOptions, DefaultMlsRules},
    psk::{ExternalPskId, PreSharedKey},
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, Group, MlsMessage,
    WireFormat,
};
use mls_rs_crypto_openssl::{OpensslCryptoError, OpensslCryptoProvider};
use std::{cmp::Ordering, collections::HashMap};

/// Represents errors that can occur during the operation of a `DistributedMlsAgent`.
///
/// This enum encapsulates both high-level protocol errors and low-level cryptographic
/// or library-specific issues. It is used throughout the library to provide meaningful
/// feedback and facilitate robust error handling.
///
/// # Variants
///
/// - `ExtraneousMlsGroup`:  
///   The agent received a welcome message for a group it was not expecting or already joined.
///
/// - `GroupNotInitialized`:  
///   An operation was attempted before the agent's send-group was initialized.
///
/// - `CipherSuiteNotAvailable`:  
///   The selected cipher suite is not supported by the configured crypto provider.
///
/// - `UnsupportedCipherSuite`:  
///   The cipher suite is unknown or lacks required metadata (e.g., hash length).
///
/// - `ExtraneousMlsMessage`:  
///   The message is malformed or irrelevant to the agent's current state.
///
/// - `MlsMessageTooOld`:  
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
#[derive(Debug)]
pub enum DistributedMlsError {
    /// Extraneous MLS group, i.e., created by a DMLS non-member OR additional group from an existing member.
    ExtraneousMlsGroup,
    /// DMLS Group not initialized.
    GroupNotInitialized,
    /// Cipher suite not available with the given crypto provider.
    CipherSuiteNotAvailable,
    /// Unknown cipher suite; this error is thrown when we do not have information on a desired cipher suite, e.g., hash function output length
    UnsupportedCipherSuite,
    /// Message cannot be processed at all and should be discarded.
    ExtraneousMlsMessage,
    /// Message is from a previous epoch and should be discarded.
    MlsMessageTooOld,
    /// Message sender unauthorized, i.e., attempted to send a message in another participant's send-group.
    UnauthorizedSender,
    /// Message cannot be processed yet; may be processed later.
    MessageDeferred(MlsMessage),
    /// Error from underlying OpenSSL library.
    OpensslCryptoError(OpensslCryptoError),
    /// Error from the MLS library.
    MlsError(MlsError),
}

impl core::fmt::Display for DistributedMlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Represents the current lifecycle state of a `DistributedMlsAgent`.
///
/// This enum is used internally to track the agent's progress through the
/// Distributed MLS protocol. It ensures that operations such as encryption,
/// message processing, and group updates are only performed when the agent
/// is in a valid state.
///
/// # Variants
///
/// - `Uninitialized`:  
///   The agent has been created but has not yet initialized its own send-group.
///
/// - `Initializing`:  
///   The agent has created its send-group and is waiting to join other participants'
///   send-groups via welcome messages.
///
/// - `Initialized`:  
///   The agent has successfully joined all expected receive-groups and is fully
///   operational for secure group communication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributedMlsState {
    /// DMLS group has not yet been established.
    Uninitialized,
    /// Own send-group created but waiting for welcome messages to join other participants' send-groups.
    Initializing,
    /// All groups created.
    Initialized,
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
    state: DistributedMlsState,
    client: Client<DistributedMlsConfig>,
    send_group: Option<Group<DistributedMlsConfig>>,
    recv_groups: HashMap<Vec<u8>, Group<DistributedMlsConfig>>,
    num_recv_groups: usize,
}

impl DistributedMlsAgent {
    /// Creates a new `DistributedMlsAgent` instance with the given identity name.
    ///
    /// This function initializes the MLS client with a predefined cipher suite
    /// (`CURVE25519_AES128`) and sets up the cryptographic and identity providers.
    /// It generates a fresh signature key pair and configures the client with
    /// default MLS rules that require path-based commits.
    ///
    /// # Arguments
    ///
    /// * `name` - A byte vector representing the identity name of the agent.
    ///
    /// # Returns
    ///
    /// A `Result` containing the initialized `DistributedMlsAgent` on success,
    /// or a `DistributedMlsError` if the cipher suite is unavailable or key generation fails.
    pub fn new(name: Vec<u8>) -> Result<Self, DistributedMlsError> {
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
        // done; the rest of the variables are given initial values
        Ok(Self {
            client,
            state: DistributedMlsState::Uninitialized,
            send_group: None,
            recv_groups: HashMap::new(),
            num_recv_groups: 0,
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
            .generate_key_package_message(ExtensionList::default(), ExtensionList::default())
            .map_err(DistributedMlsError::MlsError)
    }
    /// Initializes the agent's own send-group using key packages from other participants.
    ///
    /// This method creates a new MLS group and adds the provided participants
    /// to it. It transitions the agent's state to `Initializing` and prepares
    /// to receive welcome messages from other participants' send-groups.
    ///
    /// # Arguments
    ///
    /// * `key_package_messages` - A vector of `MlsMessage` objects representing
    ///   key packages from other participants.
    ///
    /// # Returns
    ///
    /// A `Result` containing a vector of welcome messages to be sent to the added
    /// participants, or a `DistributedMlsError` if group creation or commit fails.
    pub fn initialize(
        &mut self,
        key_package_messages: Vec<MlsMessage>,
    ) -> Result<Vec<MlsMessage>, DistributedMlsError> {
        // create send-group
        let mut send_group = self
            .client
            .create_group(ExtensionList::default(), Default::default())
            .map_err(DistributedMlsError::MlsError)?;
        // store number of recv-groups to expect
        let num_recv_groups = key_package_messages.len();
        // add participants to send-group
        let mut commit_builder = send_group.commit_builder();
        for key_package_message in key_package_messages {
            commit_builder = commit_builder
                .add_member(key_package_message)
                .map_err(DistributedMlsError::MlsError)?;
        }
        let commit = &commit_builder
            .build()
            .map_err(DistributedMlsError::MlsError)?;
        send_group
            .apply_pending_commit()
            .map_err(DistributedMlsError::MlsError)?;
        // update dmls state
        self.num_recv_groups = num_recv_groups;
        self.send_group = Some(send_group);
        self.state = DistributedMlsState::Initializing;
        // output welcome(s)
        Ok(commit.welcome_messages.clone())
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
        match self.state {
            DistributedMlsState::Uninitialized => Err(DistributedMlsError::GroupNotInitialized),
            _ => {
                let send_group = self.send_group.as_mut().unwrap();
                // commit update
                let commit_message = send_group
                    .commit_builder()
                    .build()
                    .map_err(DistributedMlsError::MlsError)?
                    .commit_message;
                send_group
                    .apply_pending_commit()
                    .map_err(DistributedMlsError::MlsError)?;
                // generate psk_id as context for exporter
                let mut psk_id_vec = Vec::from(send_group.current_epoch().to_be_bytes());
                psk_id_vec.extend(send_group.group_id().to_vec());
                // hash function length as exporter length
                let hash_length = match send_group.cipher_suite() {
                    CipherSuite::CURVE25519_AES128
                    | CipherSuite::P256_AES128
                    | CipherSuite::CURVE25519_CHACHA => Ok(32),
                    CipherSuite::CURVE448_AES256
                    | CipherSuite::P521_AES256
                    | CipherSuite::CURVE448_CHACHA
                    | CipherSuite::P384_AES256 => Ok(64),
                    _ => Err(DistributedMlsError::UnsupportedCipherSuite),
                }?;
                // export secret
                let exporter = send_group
                    .export_secret(b"exporter_psk", psk_id_vec.as_slice(), hash_length)
                    .map_err(DistributedMlsError::MlsError)?;
                // store as psk
                self.client.secret_store().insert(
                    ExternalPskId::new(psk_id_vec),
                    PreSharedKey::new(exporter.to_vec()),
                );
                // done
                Ok(commit_message)
            }
        }
    }
    /// Encrypts an application message using the agent's send-group.
    ///
    /// This method wraps the provided plaintext in an MLS application message
    /// and encrypts it using the current state of the send-group.
    ///
    /// # Arguments
    ///
    /// * `ptxt` - A byte slice representing the plaintext to encrypt.
    ///
    /// # Returns
    ///
    /// A `Result` containing the encrypted `MlsMessage`, or a `DistributedMlsError`
    /// if the group is uninitialized or encryption fails.
    pub fn encrypt(&mut self, ptxt: &[u8]) -> Result<MlsMessage, DistributedMlsError> {
        match self.state {
            DistributedMlsState::Uninitialized => Err(DistributedMlsError::GroupNotInitialized),
            _ => self
                .send_group
                .as_mut()
                .unwrap()
                .encrypt_application_message(ptxt, Vec::new())
                .map_err(DistributedMlsError::MlsError),
        }
    }
    /// Processes an incoming MLS message and updates internal state accordingly.
    ///
    /// This method handles different types of MLS messages based on the agent's
    /// current state:
    ///
    /// - In `Uninitialized`, all messages are deferred.
    /// - In `Initializing`, welcome messages are used to join other participants' send-groups.
    /// - In `Initialized`, application and commit messages are processed from known groups.
    ///
    /// It also performs PCS healing by exporting and committing PSKs when appropriate.
    ///
    /// # Arguments
    ///
    /// * `message` - The incoming `MlsMessage` to process.
    ///
    /// # Returns
    ///
    /// A `Result` containing a tuple:
    /// - A vector of `MlsMessage` objects to be sent in response (e.g., commit messages).
    /// - An optional decrypted application message payload, if applicable.
    ///
    /// Returns a `DistributedMlsError` if the message is invalid, from an unknown group,
    /// unauthorized, outdated, or cannot yet be processed.
    pub fn process(
        &mut self,
        message: MlsMessage,
    ) -> Result<(Vec<MlsMessage>, Option<Vec<u8>>), DistributedMlsError> {
        match self.state {
            DistributedMlsState::Uninitialized => {
                Err(DistributedMlsError::MessageDeferred(message))
            }
            DistributedMlsState::Initializing => match message.wire_format() {
                WireFormat::Welcome => {
                    // try to join group
                    let (new_group, _info) = self
                        .client
                        .join_group(None, &message)
                        .map_err(DistributedMlsError::MlsError)?;
                    if self
                        .send_group
                        .as_ref()
                        .unwrap()
                        .roster()
                        .member_identities_iter()
                        .any(|x| *x == new_group.member_at_index(0).unwrap().signing_identity)
                        && self.recv_groups.len() < self.num_recv_groups
                    {
                        // update state; i.e., add to recv-groups and transition to Initialized if this is the last recv-group
                        self.recv_groups
                            .insert(new_group.group_id().to_vec(), new_group);
                        if self.recv_groups.len() == self.num_recv_groups {
                            self.state = DistributedMlsState::Initialized;
                        }
                        // done
                        Ok((Vec::new(), None))
                    } else {
                        Err(DistributedMlsError::ExtraneousMlsGroup)
                    }
                }
                WireFormat::PublicMessage | WireFormat::PrivateMessage => {
                    Err(DistributedMlsError::MessageDeferred(message))
                }
                _ => Err(DistributedMlsError::ExtraneousMlsMessage),
            },
            DistributedMlsState::Initialized => match message.wire_format() {
                WireFormat::PublicMessage | WireFormat::PrivateMessage => match self
                    .recv_groups
                    .get_mut(message.group_id().unwrap())
                {
                    Some(recv_group) => {
                        match message.epoch().unwrap().cmp(&recv_group.current_epoch()) {
                            Ordering::Equal => {
                                let mut recv_group_clone = recv_group.clone();
                                match recv_group_clone.process_incoming_message(message.clone()) {
                                    Ok(received_message) => match received_message {
                                        ReceivedMessage::ApplicationMessage(decrypted_appmsg) => {
                                            if decrypted_appmsg.sender_index == 0 {
                                                Ok((
                                                    Vec::new(),
                                                    Some(decrypted_appmsg.data().to_vec()),
                                                ))
                                            } else {
                                                Err(DistributedMlsError::UnauthorizedSender)
                                            }
                                        }
                                        ReceivedMessage::Commit(decrypted_commit) => {
                                            if decrypted_commit.committer == 0 {
                                                *recv_group = recv_group_clone;
                                                if let CommitEffect::NewEpoch(new_epoch) =
                                                    decrypted_commit.effect
                                                {
                                                    if new_epoch.applied_proposals.is_empty() {
                                                        // generate psk_id as context for exporter
                                                        let mut psk_id_vec = Vec::from(
                                                            recv_group
                                                                .current_epoch()
                                                                .to_be_bytes(),
                                                        );
                                                        psk_id_vec
                                                            .extend(recv_group.group_id().to_vec());
                                                        // hash function length as exporter length
                                                        let hash_length = match recv_group.cipher_suite() {
                                                        CipherSuite::CURVE25519_AES128
                                                        | CipherSuite::P256_AES128
                                                        | CipherSuite::CURVE25519_CHACHA => Ok(32),
                                                        CipherSuite::CURVE448_AES256
                                                        | CipherSuite::P521_AES256
                                                        | CipherSuite::CURVE448_CHACHA
                                                        | CipherSuite::P384_AES256 => Ok(64),
                                                        _ => Err(
                                                            DistributedMlsError::UnsupportedCipherSuite,
                                                        ),
                                                    }?;
                                                        // export secret
                                                        let exporter = recv_group
                                                            .export_secret(
                                                                b"exporter_psk",
                                                                psk_id_vec.as_slice(),
                                                                hash_length,
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
                                                        let send_group =
                                                            self.send_group.as_mut().unwrap();
                                                        let commit_message = send_group
                                                            .commit_builder()
                                                            .add_external_psk(ExternalPskId::new(
                                                                psk_id_vec.clone(),
                                                            ))
                                                            .map_err(DistributedMlsError::MlsError)?
                                                            .build()
                                                            .map_err(DistributedMlsError::MlsError)?
                                                            .commit_message;
                                                        send_group.apply_pending_commit().map_err(
                                                            DistributedMlsError::MlsError,
                                                        )?;
                                                        Ok((vec![commit_message], None))
                                                    } else {
                                                        Ok((Vec::new(), None))
                                                    }
                                                } else {
                                                    Ok((Vec::new(), None))
                                                }
                                            } else {
                                                Err(DistributedMlsError::UnauthorizedSender)
                                            }
                                        }
                                        _ => Err(DistributedMlsError::ExtraneousMlsMessage),
                                    },
                                    Err(MlsError::MissingRequiredPsk) => {
                                        Err(DistributedMlsError::MessageDeferred(message))
                                    }
                                    Err(e) => Err(DistributedMlsError::MlsError(e)),
                                }
                            }
                            Ordering::Less => Err(DistributedMlsError::MlsMessageTooOld),
                            Ordering::Greater => Err(DistributedMlsError::MessageDeferred(message)),
                        }
                    }
                    _ => Err(DistributedMlsError::ExtraneousMlsMessage),
                },
                _ => Err(DistributedMlsError::ExtraneousMlsMessage),
            },
        }
    }
}
