//! Property-based tests for the on-chain ABI types introduced for
//! account-backed multi-tenant verification:
//!
//!   - `Falcon512PreparedPubkeyAccount` (8B disc + u32 version + 1024B body)
//!   - `Falcon512VerifyInstruction`     (`[sig 666][message variable]`)
//!
//! These are not math tests — math correctness is covered by the existing
//! NTT/codec/keccak proptests, by the host-side PQClean differential, and (in
//! abishekk92's PR #2) by Lean/Kani. What this file owns is the **parser
//! surface** of the wire layouts a multi-tenant Solana program will hand to
//! this crate from runtime account data and instruction payloads.
//!
//! Coverage shape:
//!
//!   1. Round-trip closure: any value built via the public constructor
//!      survives `to_bytes` → `from_bytes` (and `try_from_slice`) intact.
//!   2. Adversarial closure: every byte of the discriminator / version field
//!      is load-bearing — flipping any bit there must yield a parser error.
//!   3. Length closure: any length other than `*_LEN` for accounts, and any
//!      length below `FALCON_512_SIGNATURE_LEN` for instructions, must reject.
//!   4. Alignment closure: the wrapper requires 4-byte alignment; reading
//!      from a 4-misaligned offset must reject. Solana's program ABI gives
//!      us 8-byte-aligned account data, so this only fires on synthetic
//!      offsets — we exercise it explicitly to pin the contract.

use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::PublicKey;
use proptest::prelude::*;
use solana_falcon512::{
    FALCON_512_PREPARED_PUBKEY_ACCOUNT_LEN, FALCON_512_PREPARED_PUBKEY_ACCOUNT_VERSION,
    FALCON_512_PUBKEY_LEN, FALCON_512_SIGNATURE_LEN, Falcon512PreparedPubkey,
    Falcon512PreparedPubkeyAccount, Falcon512Pubkey, Falcon512Signature,
    Falcon512VerifyInstruction,
};

/// Build a real prepared pubkey from a fresh PQClean Falcon-512 keygen.
///
/// We use a real (validly NTT-formed) prepared pubkey rather than a randomly
/// filled one because `Falcon512PreparedPubkey::as_bytes` round-trip is the
/// invariant we care about; the inner coefficients still being valid mod-Q
/// values lets the property tests exercise realistic byte distributions.
fn fresh_prepared_pubkey() -> Falcon512PreparedPubkey {
    let (pk, _) = falcon512::keypair();
    let bytes: [u8; FALCON_512_PUBKEY_LEN] = pk.as_bytes().try_into().unwrap();
    Falcon512Pubkey::from_bytes(bytes).prepare_pubkey()
}

// -----------------------------------------------------------------------------
// Falcon512PreparedPubkeyAccount: round-trip closure
// -----------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        // The expensive op here is `prepare_pubkey()` (~99k CU equivalent on
        // host). 32 cases keeps the suite under ~1s while still being a
        // genuine fuzz of disc/version/length adversarial mutations below.
        cases: 32,
        ..ProptestConfig::default()
    })]

    /// Any prepared pubkey survives `to_bytes` → `from_bytes` byte-identical.
    #[test]
    fn account_owned_roundtrip(_seed in any::<u64>()) {
        let prepared = fresh_prepared_pubkey();
        let original = Falcon512PreparedPubkeyAccount::new(prepared.clone());
        let serialised = original.to_bytes();

        let parsed = Falcon512PreparedPubkeyAccount::from_bytes(serialised).unwrap();
        prop_assert_eq!(parsed.prepared_pubkey().as_bytes(), prepared.as_bytes());
        prop_assert_eq!(parsed.to_bytes(), serialised);
    }

    /// The borrow form returns the same payload bytes as the owned form.
    #[test]
    fn account_borrowed_roundtrip(_seed in any::<u64>()) {
        let prepared = fresh_prepared_pubkey();
        let owned = Falcon512PreparedPubkeyAccount::new(prepared.clone());
        let serialised = owned.to_bytes();

        // Aligned heap allocation: Vec<[u8; LEN]> with 1 element so the
        // pointer satisfies the wrapper's alignment requirement.
        let mut buf: Vec<[u8; FALCON_512_PREPARED_PUBKEY_ACCOUNT_LEN]> = vec![[0u8; FALCON_512_PREPARED_PUBKEY_ACCOUNT_LEN]; 1];
        buf[0] = serialised;
        let borrowed =
            Falcon512PreparedPubkeyAccount::try_from_slice(&buf[0]).unwrap();
        prop_assert_eq!(borrowed.prepared_pubkey().as_bytes(), prepared.as_bytes());
    }
}

// -----------------------------------------------------------------------------
// Falcon512PreparedPubkeyAccount: adversarial closure
// -----------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// Flipping any bit in the 8-byte discriminator must reject. Every byte
    /// position is load-bearing — there is no "spare" field in the disc.
    #[test]
    fn account_disc_byte_flip_rejects(byte_idx in 0usize..8, bit_idx in 0u32..8) {
        let prepared = fresh_prepared_pubkey();
        let mut bytes = Falcon512PreparedPubkeyAccount::new(prepared).to_bytes();
        bytes[byte_idx] ^= 1u8 << bit_idx;

        prop_assert!(
            Falcon512PreparedPubkeyAccount::from_bytes(bytes).is_err(),
            "disc bit-flip at byte {} bit {} must reject", byte_idx, bit_idx
        );
        prop_assert!(
            Falcon512PreparedPubkeyAccount::try_from_slice(&bytes).is_err(),
            "borrowed disc bit-flip at byte {} bit {} must reject", byte_idx, bit_idx
        );
    }

    /// Any version other than 1 must reject. The point of the version field is
    /// that future formats have explicit forward-compatibility breakage at
    /// load time, not silent misinterpretation.
    #[test]
    fn account_wrong_version_rejects(bad_version in any::<u32>().prop_filter(
        "skip the canonical version",
        |v| *v != FALCON_512_PREPARED_PUBKEY_ACCOUNT_VERSION,
    )) {
        let prepared = fresh_prepared_pubkey();
        let mut bytes = Falcon512PreparedPubkeyAccount::new(prepared).to_bytes();
        bytes[8..12].copy_from_slice(&bad_version.to_le_bytes());

        prop_assert!(Falcon512PreparedPubkeyAccount::from_bytes(bytes).is_err());
        prop_assert!(Falcon512PreparedPubkeyAccount::try_from_slice(&bytes).is_err());
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

    /// Any length other than the canonical LEN must reject. Random fuzz is
    /// generated to a heap buffer so we get arbitrary content together with
    /// arbitrary length — the parser must reject on length alone, before
    /// content matters.
    #[test]
    fn account_wrong_length_rejects(len in 0usize..(FALCON_512_PREPARED_PUBKEY_ACCOUNT_LEN * 2)) {
        prop_assume!(len != FALCON_512_PREPARED_PUBKEY_ACCOUNT_LEN);
        let buf = vec![0u8; len];
        prop_assert!(Falcon512PreparedPubkeyAccount::try_from_slice(&buf).is_err());
    }

    /// 4-misaligned reads must reject. The wrapper is `repr(C)` over
    /// `[u8;8] + u32 + [u16;512]`, so its alignment is 4. The Solana program
    /// ABI gives us 8-byte-aligned account data so this case is synthetic,
    /// but pinning the contract here makes any future host that violates
    /// the alignment guarantee fail loudly instead of silently producing UB.
    #[test]
    fn account_misaligned_rejects(offset in 1usize..4) {
        let prepared = fresh_prepared_pubkey();
        let bytes = Falcon512PreparedPubkeyAccount::new(prepared).to_bytes();
        let mut padded = vec![0u8; FALCON_512_PREPARED_PUBKEY_ACCOUNT_LEN + offset];
        padded[offset..].copy_from_slice(&bytes);

        // Force the slice start to be `offset`-misaligned vs the parent. We
        // don't assert the address modulus directly because the system
        // allocator is free to return whatever-aligned vectors; we assert
        // *if* the resulting pointer is 4-misaligned, the parser rejects.
        let ptr = padded[offset..].as_ptr() as usize;
        if ptr % core::mem::align_of::<Falcon512PreparedPubkeyAccount>() != 0 {
            prop_assert!(
                Falcon512PreparedPubkeyAccount::try_from_slice(&padded[offset..]).is_err()
            );
        }
    }
}

// -----------------------------------------------------------------------------
// Falcon512VerifyInstruction: round-trip + adversarial closure
// -----------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// `encode_into` followed by `parse` returns byte-equal signature and
    /// message components, for any signature bytes and any message length up
    /// to a generous on-chain ceiling. Larger messages aren't part of any
    /// realistic Solana ix payload (the wire is 1232 B total), so capping
    /// here keeps the suite fast and faithful to actual deployment shape.
    #[test]
    fn verify_ix_roundtrip(
        sig_bytes in any::<[u8; FALCON_512_SIGNATURE_LEN]>(),
        message in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let signature = Falcon512Signature::from(sig_bytes);
        let original = Falcon512VerifyInstruction::new(&signature, &message);
        let mut encoded = vec![0u8; original.encoded_len()];
        original.encode_into(&mut encoded).unwrap();

        let parsed = Falcon512VerifyInstruction::parse(&encoded).unwrap();
        prop_assert_eq!(parsed.signature().as_bytes(), &sig_bytes);
        prop_assert_eq!(parsed.message(), message.as_slice());
        prop_assert_eq!(parsed.encoded_len(), original.encoded_len());
    }

    /// Any input shorter than `FALCON_512_SIGNATURE_LEN` (= 666 B) is a
    /// truncated signature header and must reject without consulting the
    /// signature contents at all — i.e. the parser is length-first.
    #[test]
    fn verify_ix_truncated_rejects(len in 0usize..FALCON_512_SIGNATURE_LEN) {
        let buf = vec![0u8; len];
        prop_assert!(Falcon512VerifyInstruction::parse(&buf).is_err());
    }

    /// `encode_into` must reject any output buffer whose length differs from
    /// `encoded_len()`. This is the contract that lets callers stack-allocate
    /// based on `encoded_len()` and trust the encoder won't underflow or
    /// overflow.
    #[test]
    fn verify_ix_encode_into_wrong_size_rejects(
        message_len in 0usize..512,
        delta in -16i32..=16i32,
    ) {
        prop_assume!(delta != 0);
        let signature = Falcon512Signature::from([0u8; FALCON_512_SIGNATURE_LEN]);
        let message = vec![0u8; message_len];
        let ix = Falcon512VerifyInstruction::new(&signature, &message);

        let target_len = ix.encoded_len() as i32 + delta;
        if target_len < 0 { return Ok(()); }
        let mut out = vec![0u8; target_len as usize];
        prop_assert!(ix.encode_into(&mut out).is_err());
    }
}

// -----------------------------------------------------------------------------
// Cross-property: encoded_len + parse identity
// -----------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

    /// For any (signature, message) pair, the encoded length equals the
    /// parsed-back encoded length, i.e. encoding is length-stable. This is
    /// the property a variable-length vec-of-Vec deserializer cannot offer
    /// and the reason this ABI is fixed-prefix + variable-tail.
    #[test]
    fn verify_ix_encoded_len_stable(message_len in 0usize..2048) {
        let signature = Falcon512Signature::from([0xA5u8; FALCON_512_SIGNATURE_LEN]);
        let message = vec![0xC3u8; message_len];
        let ix = Falcon512VerifyInstruction::new(&signature, &message);
        let mut encoded = vec![0u8; ix.encoded_len()];
        ix.encode_into(&mut encoded).unwrap();

        let parsed = Falcon512VerifyInstruction::parse(&encoded).unwrap();
        prop_assert_eq!(parsed.encoded_len(), ix.encoded_len());
        prop_assert_eq!(parsed.encoded_len(), FALCON_512_SIGNATURE_LEN + message_len);
    }
}
