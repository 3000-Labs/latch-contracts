#![no_std]

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
    pub ed25519_verifier: Address,
    pub secp256k1_verifier: Address,
    pub webauthn_verifier: Address,
    pub threshold_policy: Address,
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
        ed25519_verifier: Address,
        secp256k1_verifier: Address,
        webauthn_verifier: Address,
        threshold_policy: Address,
    ) {
        if env.storage().instance().has(&DataKey::Config) {
            panic_with_error!(&env, FactoryError::AlreadyInitialized);
        }

        let config = FactoryConfig {
            smart_account_wasm_hash,
            ed25519_verifier,
            secp256k1_verifier,
            webauthn_verifier,
            threshold_policy,
        };
        env.storage().instance().set(&DataKey::Config, &config);
        env.storage().instance().extend_ttl(100, 518400);
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

        let signers = build_account_signers(&env, &config, &normalized.signers);
        let policies = build_account_policies(&env, &config, &normalized.effective_threshold, signers.len());

        let account = deployer.deploy_v2(config.smart_account_wasm_hash, (&signers, &policies));
        AccountCreated { account: account.clone() }.publish(&env);
        account
    }

    pub fn get_verifier(env: Env, signer_kind: SignerKind) -> Address {
        let config = get_config(&env);
        match signer_kind {
            SignerKind::Ed25519 => config.ed25519_verifier,
            SignerKind::Secp256k1 => config.secp256k1_verifier,
            SignerKind::WebAuthn => config.webauthn_verifier,
        }
    }

    pub fn get_threshold_policy(env: Env) -> Address {
        get_config(&env).threshold_policy
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
    if params.signers.is_empty() {
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

fn build_account_signers(
    env: &Env,
    config: &FactoryConfig,
    signers: &Vec<ExternalSignerInit>,
) -> Vec<Signer> {
    let mut account_signers = Vec::new(env);
    for signer in signers.iter() {
        let verifier = match signer.signer_kind {
            SignerKind::Ed25519 => config.ed25519_verifier.clone(),
            SignerKind::Secp256k1 => config.secp256k1_verifier.clone(),
            SignerKind::WebAuthn => config.webauthn_verifier.clone(),
        };
        account_signers.push_back(Signer::External(verifier, signer.key_data));
    }
    account_signers
}

fn build_account_policies(
    env: &Env,
    config: &FactoryConfig,
    threshold: &u32,
    signer_count: u32,
) -> Map<Address, Val> {
    let mut policies = Map::new(env);

    if signer_count > 1 {
        let install_params = SimpleThresholdAccountParams { threshold: *threshold };
        policies.set(config.threshold_policy.clone(), install_params.into_val(env));
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

fn signer_kind_code(kind: SignerKind) -> u8 {
    match kind {
        SignerKind::Ed25519 => 0x01,
        SignerKind::Secp256k1 => 0x02,
        SignerKind::WebAuthn => 0x03,
    }
}

#[cfg(test)]
mod test;
