#![no_std]
#![allow(clippy::ref_option)]

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, Address,
    Bytes, BytesN, Env, IntoVal, Map, Val, Vec,
};
use stellar_accounts::{
    policies::simple_threshold::SimpleThresholdAccountParams, smart_account::Signer,
};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Config,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactoryConfig {
    pub smart_account_wasm_hash: BytesN<32>,
    pub ed25519_verifier_wasm_hash: BytesN<32>,
    pub secp256k1_verifier_wasm_hash: BytesN<32>,
    pub webauthn_verifier_wasm_hash: BytesN<32>,
    pub threshold_policy_wasm_hash: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum SignerKind {
    Ed25519,
    Secp256k1,
    WebAuthn,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ExternalSignerInit {
    pub signer_kind: SignerKind,
    pub key_data: Bytes,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountInitParams {
    pub signers: Vec<ExternalSignerInit>,
    pub threshold: Option<u32>,
    pub account_salt: BytesN<32>,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum FactoryError {
    AlreadyInitialized = 1,
    MissingConfig = 2,
    NoSigners = 3,
    DuplicateSigner = 4,
    MissingThreshold = 5,
    InvalidThreshold = 6,
    InvalidEd25519Key = 7,
    InvalidSecp256k1Key = 8,
    InvalidWebAuthnKey = 9,
}

#[contractevent]
pub struct AccountCreated {
    pub account: Address,
}

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn __constructor(
        env: Env,
        smart_account_wasm_hash: BytesN<32>,
        ed25519_verifier_wasm_hash: BytesN<32>,
        secp256k1_verifier_wasm_hash: BytesN<32>,
        webauthn_verifier_wasm_hash: BytesN<32>,
        threshold_policy_wasm_hash: BytesN<32>,
    ) {
        if env.storage().instance().has(&DataKey::Config) {
            panic_with_error!(&env, FactoryError::AlreadyInitialized);
        }

        let config = FactoryConfig {
            smart_account_wasm_hash,
            ed25519_verifier_wasm_hash,
            secp256k1_verifier_wasm_hash,
            webauthn_verifier_wasm_hash,
            threshold_policy_wasm_hash,
        };
        env.storage().instance().set(&DataKey::Config, &config);
    }

    pub fn get_account_address(env: Env, params: AccountInitParams) -> Address {
        let normalized = normalize_params(&env, params);
        env.deployer()
            .with_current_contract(compute_account_deploy_salt(&env, &normalized))
            .deployed_address()
    }

    pub fn create_account(env: Env, params: AccountInitParams) -> Address {
        let config = get_config(&env);
        let normalized = normalize_params(&env, params);
        let account_salt = compute_account_deploy_salt(&env, &normalized);
        let deployer = env.deployer().with_current_contract(account_salt);
        let account_address = deployer.deployed_address();

        if account_address.executable().is_some() {
            return account_address;
        }

        let signers = build_account_signers(&env, &normalized.signers);
        let policies = build_account_policies(&env, &normalized.effective_threshold, signers.len());

        let account = deployer.deploy_v2(config.smart_account_wasm_hash, (&signers, &policies));
        AccountCreated { account: account.clone() }.publish(&env);
        account
    }

    pub fn get_verifier(env: Env, signer_kind: SignerKind) -> Address {
        singleton_address(&env, singleton_salt(&env, signer_kind_label(signer_kind)))
    }

    pub fn get_threshold_policy(env: Env) -> Address {
        singleton_address(
            &env,
            singleton_salt(&env, b"latch.factory.policy.threshold.v1"),
        )
    }
}

#[derive(Clone)]
struct NormalizedParams {
    signers: Vec<ExternalSignerInit>,
    effective_threshold: u32,
    account_salt: BytesN<32>,
}

fn get_config(env: &Env) -> FactoryConfig {
    env.storage().instance().extend_ttl(100, 518400);
    env.storage()
        .instance()
        .get(&DataKey::Config)
        .unwrap_or_else(|| panic_with_error!(env, FactoryError::MissingConfig))
}

fn normalize_params(env: &Env, params: AccountInitParams) -> NormalizedParams {
    if params.signers.len() == 0 {
        panic_with_error!(env, FactoryError::NoSigners);
    }

    let canonical_signers = canonicalize_signers(env, &params.signers);
    let signer_count = canonical_signers.len();

    let effective_threshold = if signer_count == 1 {
        match params.threshold {
            None | Some(1) => 1,
            Some(_) => panic_with_error!(env, FactoryError::InvalidThreshold),
        }
    } else {
        match params.threshold {
            Some(threshold) if threshold >= 1 && threshold <= signer_count => threshold,
            Some(_) => panic_with_error!(env, FactoryError::InvalidThreshold),
            None => panic_with_error!(env, FactoryError::MissingThreshold),
        }
    };

    NormalizedParams {
        signers: canonical_signers,
        effective_threshold,
        account_salt: params.account_salt,
    }
}

fn canonicalize_signers(env: &Env, signers: &Vec<ExternalSignerInit>) -> Vec<ExternalSignerInit> {
    let mut canonical = Vec::new(env);

    for signer in signers.iter() {
        validate_key_shape(env, &signer);

        match canonical.binary_search(&signer) {
            Ok(_) => panic_with_error!(env, FactoryError::DuplicateSigner),
            Err(pos) => canonical.insert(pos, signer),
        }
    }

    canonical
}

fn validate_key_shape(env: &Env, signer: &ExternalSignerInit) {
    match signer.signer_kind {
        SignerKind::Ed25519 => {
            if signer.key_data.len() != 32 {
                panic_with_error!(env, FactoryError::InvalidEd25519Key);
            }
        }
        SignerKind::Secp256k1 => {
            if signer.key_data.len() != 65 || signer.key_data.get(0).unwrap_or(0) != 0x04 {
                panic_with_error!(env, FactoryError::InvalidSecp256k1Key);
            }
        }
        SignerKind::WebAuthn => {
            if signer.key_data.len() <= 65 || signer.key_data.get(0).unwrap_or(0) != 0x04 {
                panic_with_error!(env, FactoryError::InvalidWebAuthnKey);
            }
        }
    }
}

fn build_account_signers(env: &Env, signers: &Vec<ExternalSignerInit>) -> Vec<Signer> {
    let mut account_signers = Vec::new(env);
    for signer in signers.iter() {
        let verifier = ensure_verifier(env, signer.signer_kind);
        account_signers.push_back(Signer::External(verifier, signer.key_data));
    }
    account_signers
}

fn build_account_policies(env: &Env, threshold: &u32, signer_count: u32) -> Map<Address, Val> {
    let mut policies = Map::new(env);

    if signer_count > 1 {
        let threshold_policy = ensure_threshold_policy(env);
        let install_params = SimpleThresholdAccountParams {
            threshold: *threshold,
        };
        policies.set(threshold_policy, install_params.into_val(env));
    }

    policies
}

fn compute_account_deploy_salt(env: &Env, params: &NormalizedParams) -> BytesN<32> {
    let mut preimage = Bytes::from_slice(env, b"latch.factory.account.v1");
    preimage.extend_from_array(&params.account_salt.to_array());
    preimage.extend_from_array(&params.signers.len().to_be_bytes());

    for signer in params.signers.iter() {
        preimage.extend_from_array(&[signer_kind_code(signer.signer_kind)]);
        preimage.extend_from_array(&signer.key_data.len().to_be_bytes());
        preimage.append(&signer.key_data);
    }

    preimage.extend_from_array(&params.effective_threshold.to_be_bytes());

    env.crypto().sha256(&preimage).to_bytes()
}

fn ensure_verifier(env: &Env, signer_kind: SignerKind) -> Address {
    let config = get_config(env);
    let (salt, wasm_hash) = match signer_kind {
        SignerKind::Ed25519 => (
            singleton_salt(env, signer_kind_label(signer_kind)),
            config.ed25519_verifier_wasm_hash,
        ),
        SignerKind::Secp256k1 => (
            singleton_salt(env, signer_kind_label(signer_kind)),
            config.secp256k1_verifier_wasm_hash,
        ),
        SignerKind::WebAuthn => (
            singleton_salt(env, signer_kind_label(signer_kind)),
            config.webauthn_verifier_wasm_hash,
        ),
    };

    ensure_singleton_contract(env, salt, wasm_hash)
}

fn ensure_threshold_policy(env: &Env) -> Address {
    let config = get_config(env);
    let salt = singleton_salt(env, b"latch.factory.policy.threshold.v1");
    ensure_singleton_contract(env, salt, config.threshold_policy_wasm_hash)
}

fn ensure_singleton_contract(env: &Env, salt: BytesN<32>, wasm_hash: BytesN<32>) -> Address {
    let deployer = env.deployer().with_current_contract(salt);
    let address = deployer.deployed_address();

    if address.executable().is_none() {
        deployer.deploy_v2(wasm_hash, ());
    }

    address
}

fn singleton_address(env: &Env, salt: BytesN<32>) -> Address {
    env.deployer()
        .with_current_contract(salt)
        .deployed_address()
}

fn singleton_salt(env: &Env, label: &[u8]) -> BytesN<32> {
    env.crypto()
        .sha256(&Bytes::from_slice(env, label))
        .to_bytes()
}

fn signer_kind_code(kind: SignerKind) -> u8 {
    match kind {
        SignerKind::Ed25519 => 0x01,
        SignerKind::Secp256k1 => 0x02,
        SignerKind::WebAuthn => 0x03,
    }
}

fn signer_kind_label(kind: SignerKind) -> &'static [u8] {
    match kind {
        SignerKind::Ed25519 => b"latch.factory.verifier.ed25519.v1",
        SignerKind::Secp256k1 => b"latch.factory.verifier.secp256k1.v1",
        SignerKind::WebAuthn => b"latch.factory.verifier.webauthn.v1",
    }
}

#[cfg(test)]
mod test;
