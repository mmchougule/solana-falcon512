use mollusk_svm::Mollusk;
use solana_account::Account;
use solana_address::Address;
use solana_falcon512::{
    Falcon512PreparedPubkeyAccount, Falcon512Pubkey, Falcon512Signature, Falcon512VerifyInstruction,
};
use solana_instruction::{AccountMeta, Instruction};

const SIG_LEN: usize = 666;

// Static fixture — fixed (pubkey, signature, message) triple. Fully
// deterministic CU measurement: every test run signs exactly the same bytes
// because the signature is baked into the repo. Regenerate via
// `cargo test --release -p host-tests --test fixtures -- --ignored --nocapture`.
const SIG: [u8; SIG_LEN] = *include_bytes!("fixtures/sample_sig.bin");
const MSG: &[u8] = b"deterministic falcon-512 verify benchmark";

fn build_ix_data(sig: [u8; SIG_LEN], msg: &[u8]) -> Vec<u8> {
    let signature = Falcon512Signature::from(sig);
    let instruction = Falcon512VerifyInstruction::new(&signature, msg);
    let mut data = vec![0u8; instruction.encoded_len()];
    instruction
        .encode_into(&mut data)
        .expect("instruction buffer should match encoded len");
    data
}

// `cargo test-sbf` builds the SBF program and sets `SBF_OUT_DIR` to its
// `target/deploy` directory; Mollusk picks the `.so` up from there.
fn make_mollusk() -> (Mollusk, Address) {
    let program_id = Address::new_unique();
    let mollusk = Mollusk::new(&program_id, "../target/deploy/program");
    (mollusk, program_id)
}

fn prepared_pubkey_account_bytes() -> Vec<u8> {
    let prepared =
        Falcon512Pubkey::from_bytes(*include_bytes!("fixtures/falcon.pk")).prepare_pubkey();
    Falcon512PreparedPubkeyAccount::new(prepared)
        .to_bytes()
        .to_vec()
}

#[test]
fn verify_fixed_message() {
    let (mollusk, program_id) = make_mollusk();
    let ix = Instruction {
        program_id,
        accounts: vec![],
        data: build_ix_data(SIG, MSG),
    };
    let result = mollusk.process_instruction(&ix, &[]);
    assert!(
        !result.program_result.is_err(),
        "verify failed: {:?}",
        result.program_result
    );
    println!(
        "verify_fixed_message OK — compute units consumed: {}",
        result.compute_units_consumed
    );
}

#[test]
fn rejects_tampered_message() {
    let (mollusk, program_id) = make_mollusk();
    let mut tampered_msg = MSG.to_vec();
    tampered_msg[0] ^= 0x01;
    let ix = Instruction {
        program_id,
        accounts: vec![],
        data: build_ix_data(SIG, &tampered_msg),
    };
    let result = mollusk.process_instruction(&ix, &[]);
    assert!(
        result.program_result.is_err(),
        "expected failure on tampered msg, got: {:?}",
        result.program_result
    );
}

#[test]
fn rejects_tampered_signature() {
    let (mollusk, program_id) = make_mollusk();
    let mut tampered_sig = SIG;
    // Flip a bit inside the signature payload (past header + nonce).
    tampered_sig[100] ^= 0x01;
    let ix = Instruction {
        program_id,
        accounts: vec![],
        data: build_ix_data(tampered_sig, MSG),
    };
    let result = mollusk.process_instruction(&ix, &[]);
    assert!(
        result.program_result.is_err(),
        "expected failure on tampered sig, got: {:?}",
        result.program_result
    );
}

#[test]
fn verify_with_prepared_pubkey_account() {
    let (mollusk, program_id) = make_mollusk();
    let prepared_key = Address::new_unique();
    let ix = Instruction {
        program_id,
        accounts: vec![AccountMeta::new_readonly(prepared_key, false)],
        data: build_ix_data(SIG, MSG),
    };
    let accounts = vec![(
        prepared_key,
        Account {
            lamports: 1,
            data: prepared_pubkey_account_bytes(),
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    )];

    let result = mollusk.process_instruction(&ix, &accounts);
    assert!(
        !result.program_result.is_err(),
        "verify with account-backed prepared key failed: {:?}",
        result.program_result
    );
    println!(
        "verify_with_prepared_pubkey_account OK — compute units consumed: {}",
        result.compute_units_consumed
    );
}

#[test]
fn rejects_invalid_prepared_pubkey_account_header() {
    let (mollusk, program_id) = make_mollusk();
    let prepared_key = Address::new_unique();
    let ix = Instruction {
        program_id,
        accounts: vec![AccountMeta::new_readonly(prepared_key, false)],
        data: build_ix_data(SIG, MSG),
    };
    let mut account_data = prepared_pubkey_account_bytes();
    account_data[0] ^= 0x01;
    let accounts = vec![(
        prepared_key,
        Account {
            lamports: 1,
            data: account_data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    )];

    let result = mollusk.process_instruction(&ix, &accounts);
    assert!(
        result.program_result.is_err(),
        "expected failure on malformed prepared-pubkey account, got: {:?}",
        result.program_result
    );
}

#[test]
fn rejects_truncated_instruction_data() {
    let (mollusk, program_id) = make_mollusk();
    let ix = Instruction {
        program_id,
        accounts: vec![],
        data: vec![0u8; SIG_LEN - 1],
    };

    let result = mollusk.process_instruction(&ix, &[]);
    assert!(
        result.program_result.is_err(),
        "expected failure on truncated instruction payload, got: {:?}",
        result.program_result
    );
}

#[test]
fn rejects_prepared_pubkey_account_with_wrong_owner() {
    let (mollusk, program_id) = make_mollusk();
    let prepared_key = Address::new_unique();
    let wrong_owner = Address::new_unique();
    let ix = Instruction {
        program_id,
        accounts: vec![AccountMeta::new_readonly(prepared_key, false)],
        data: build_ix_data(SIG, MSG),
    };
    let accounts = vec![(
        prepared_key,
        Account {
            lamports: 1,
            data: prepared_pubkey_account_bytes(),
            owner: wrong_owner,
            executable: false,
            rent_epoch: 0,
        },
    )];

    let result = mollusk.process_instruction(&ix, &accounts);
    assert!(
        result.program_result.is_err(),
        "expected failure on wrong-owner prepared-pubkey account, got: {:?}",
        result.program_result
    );
}

#[test]
fn rejects_extra_accounts() {
    let (mollusk, program_id) = make_mollusk();
    let prepared_key = Address::new_unique();
    let extra = Address::new_unique();
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(prepared_key, false),
            AccountMeta::new_readonly(extra, false),
        ],
        data: build_ix_data(SIG, MSG),
    };
    let accounts = vec![
        (
            prepared_key,
            Account {
                lamports: 1,
                data: prepared_pubkey_account_bytes(),
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        ),
        (
            extra,
            Account {
                lamports: 1,
                data: vec![],
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        ),
    ];

    let result = mollusk.process_instruction(&ix, &accounts);
    assert!(
        result.program_result.is_err(),
        "expected failure on extra accounts, got: {:?}",
        result.program_result
    );
}
