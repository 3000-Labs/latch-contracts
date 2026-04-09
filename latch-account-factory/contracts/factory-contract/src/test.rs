#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::{Bytes, BytesN, Env};

fn zero_hash(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0; 32])
}

fn install_factory(env: &Env) -> ContractClient<'_> {
    let contract_id = env.register(
        Contract,
        (
            zero_hash(env),
            zero_hash(env),
            zero_hash(env),
            zero_hash(env),
            zero_hash(env),
        ),
    );

    ContractClient::new(env, &contract_id)
}

fn ed25519_signer(env: &Env, byte: u8) -> ExternalSignerInit {
    ExternalSignerInit {
        signer_kind: SignerKind::Ed25519,
        key_data: Bytes::from_array(env, &[byte; 32]),
    }
}

fn secp256k1_signer(env: &Env, byte: u8) -> ExternalSignerInit {
    let mut raw = [byte; 65];
    raw[0] = 0x04;

    ExternalSignerInit {
        signer_kind: SignerKind::Secp256k1,
        key_data: Bytes::from_array(env, &raw),
    }
}

#[test]
fn same_params_same_address() {
    let env = Env::default();
    let client = install_factory(&env);

    let params = AccountInitParams {
        signers: soroban_sdk::vec![&env, ed25519_signer(&env, 7)],
        threshold: None,
        account_salt: BytesN::from_array(&env, &[9; 32]),
    };

    let addr_1 = client.get_account_address(&params);
    let addr_2 = client.get_account_address(&params);

    assert_eq!(addr_1, addr_2);
}

#[test]
fn signer_order_does_not_change_address() {
    let env = Env::default();
    let client = install_factory(&env);

    let signer_a = ed25519_signer(&env, 1);
    let signer_b = secp256k1_signer(&env, 2);
    let salt = BytesN::from_array(&env, &[3; 32]);

    let params_1 = AccountInitParams {
        signers: soroban_sdk::vec![&env, signer_a.clone(), signer_b.clone()],
        threshold: Some(2),
        account_salt: salt.clone(),
    };
    let params_2 = AccountInitParams {
        signers: soroban_sdk::vec![&env, signer_b, signer_a],
        threshold: Some(2),
        account_salt: salt,
    };

    let addr_1 = client.get_account_address(&params_1);
    let addr_2 = client.get_account_address(&params_2);

    assert_eq!(addr_1, addr_2);
}

#[test]
fn account_salt_changes_address() {
    let env = Env::default();
    let client = install_factory(&env);

    let signers = soroban_sdk::vec![&env, ed25519_signer(&env, 5)];
    let params_1 = AccountInitParams {
        signers: signers.clone(),
        threshold: None,
        account_salt: BytesN::from_array(&env, &[1; 32]),
    };
    let params_2 = AccountInitParams {
        signers,
        threshold: None,
        account_salt: BytesN::from_array(&env, &[2; 32]),
    };

    let addr_1 = client.get_account_address(&params_1);
    let addr_2 = client.get_account_address(&params_2);

    assert_ne!(addr_1, addr_2);
}

#[test]
fn duplicate_signers_are_rejected() {
    let env = Env::default();
    let client = install_factory(&env);
    let signer = ed25519_signer(&env, 9);

    let params = AccountInitParams {
        signers: soroban_sdk::vec![&env, signer.clone(), signer],
        threshold: Some(2),
        account_salt: BytesN::from_array(&env, &[7; 32]),
    };

    assert!(client.try_get_account_address(&params).is_err());
}

#[test]
fn multisig_requires_explicit_threshold() {
    let env = Env::default();
    let client = install_factory(&env);

    let params = AccountInitParams {
        signers: soroban_sdk::vec![&env, ed25519_signer(&env, 1), ed25519_signer(&env, 2)],
        threshold: None,
        account_salt: BytesN::from_array(&env, &[8; 32]),
    };

    assert!(client.try_get_account_address(&params).is_err());
}

#[test]
fn threshold_zero_is_rejected() {
    let env = Env::default();
    let client = install_factory(&env);

    let params = AccountInitParams {
        signers: soroban_sdk::vec![&env, ed25519_signer(&env, 1), ed25519_signer(&env, 2)],
        threshold: Some(0),
        account_salt: BytesN::from_array(&env, &[1; 32]),
    };

    assert!(client.try_get_account_address(&params).is_err());
}

#[test]
fn threshold_above_signer_count_is_rejected() {
    let env = Env::default();
    let client = install_factory(&env);

    let params = AccountInitParams {
        signers: soroban_sdk::vec![&env, ed25519_signer(&env, 1), ed25519_signer(&env, 2)],
        threshold: Some(3),
        account_salt: BytesN::from_array(&env, &[2; 32]),
    };

    assert!(client.try_get_account_address(&params).is_err());
}

#[test]
fn different_key_data_changes_address() {
    let env = Env::default();
    let client = install_factory(&env);

    let salt = BytesN::from_array(&env, &[5; 32]);
    let params_1 = AccountInitParams {
        signers: soroban_sdk::vec![&env, ed25519_signer(&env, 1)],
        threshold: None,
        account_salt: salt.clone(),
    };
    let params_2 = AccountInitParams {
        signers: soroban_sdk::vec![&env, ed25519_signer(&env, 2)],
        threshold: None,
        account_salt: salt,
    };

    let addr_1 = client.get_account_address(&params_1);
    let addr_2 = client.get_account_address(&params_2);

    assert_ne!(addr_1, addr_2);
}

#[test]
fn invalid_ed25519_key_is_rejected() {
    let env = Env::default();
    let client = install_factory(&env);

    // Ed25519 key must be exactly 32 bytes
    let bad_signer = ExternalSignerInit {
        signer_kind: SignerKind::Ed25519,
        key_data: Bytes::from_array(&env, &[1u8; 31]),
    };
    let params = AccountInitParams {
        signers: soroban_sdk::vec![&env, bad_signer],
        threshold: None,
        account_salt: BytesN::from_array(&env, &[6; 32]),
    };

    assert!(client.try_get_account_address(&params).is_err());
}

#[test]
fn invalid_secp256k1_key_is_rejected() {
    let env = Env::default();
    let client = install_factory(&env);

    // Secp256k1 key must be 65 bytes with 0x04 prefix — wrong prefix here
    let mut raw = [1u8; 65];
    raw[0] = 0x02; // compressed prefix, not uncompressed
    let bad_signer = ExternalSignerInit {
        signer_kind: SignerKind::Secp256k1,
        key_data: Bytes::from_array(&env, &raw),
    };
    let params = AccountInitParams {
        signers: soroban_sdk::vec![&env, bad_signer],
        threshold: None,
        account_salt: BytesN::from_array(&env, &[7; 32]),
    };

    assert!(client.try_get_account_address(&params).is_err());
}

#[test]
fn invalid_webauthn_key_is_rejected() {
    let env = Env::default();
    let client = install_factory(&env);

    // WebAuthn key must be >65 bytes with 0x04 prefix — exactly 65 bytes is too short
    let mut raw = [1u8; 65];
    raw[0] = 0x04;
    let bad_signer = ExternalSignerInit {
        signer_kind: SignerKind::WebAuthn,
        key_data: Bytes::from_array(&env, &raw),
    };
    let params = AccountInitParams {
        signers: soroban_sdk::vec![&env, bad_signer],
        threshold: None,
        account_salt: BytesN::from_array(&env, &[8; 32]),
    };

    assert!(client.try_get_account_address(&params).is_err());
}
