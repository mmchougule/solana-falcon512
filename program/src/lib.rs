use solana_account_info::{next_account_info, AccountInfo};
use solana_falcon512::{
    Falcon512PreparedPubkey, Falcon512PreparedPubkeyAccount, Falcon512Pubkey,
    Falcon512VerifyInstruction,
};
use solana_program_entrypoint::entrypoint_no_alloc;
use solana_program_entrypoint::ProgramResult;
use solana_program_error::ProgramError as FalconProgramError;
use solana_program_error_legacy::ProgramError as EntryProgramError;
use solana_pubkey::Pubkey;

// Prepared (decoded + NTT-transformed) pubkey, computed at compile time so the
// program skips the per-call pubkey decode + forward NTT.
pub const PREPARED_PUBKEY: Falcon512PreparedPubkey = {
    let pk = Falcon512Pubkey::from_bytes(*include_bytes!("../tests/fixtures/falcon.pk"));
    pk.prepare_pubkey()
};

entrypoint_no_alloc!(process_instruction);

/// Custom program error returned when signature verification fails.
const ERR_VERIFY_FAILED: u32 = 3;

fn map_falcon_error(err: FalconProgramError) -> EntryProgramError {
    match err {
        FalconProgramError::InvalidArgument => EntryProgramError::InvalidArgument,
        FalconProgramError::InvalidInstructionData => EntryProgramError::InvalidInstructionData,
        FalconProgramError::AccountBorrowFailed => EntryProgramError::AccountBorrowFailed,
        FalconProgramError::ArithmeticOverflow => EntryProgramError::ArithmeticOverflow,
        FalconProgramError::Custom(code) => EntryProgramError::Custom(code),
        _ => EntryProgramError::InvalidArgument,
    }
}

/// Solana SBF example verifier.
///
/// Account layout:
///
/// - zero accounts: verify against the compile-time `PREPARED_PUBKEY`
/// - one readonly account: interpret account data as a
///   `Falcon512PreparedPubkeyAccount` and verify against it
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction =
        Falcon512VerifyInstruction::parse(instruction_data).map_err(map_falcon_error)?;

    let verified = if accounts.is_empty() {
        instruction
            .signature()
            .verify_with_prepared(instruction.message(), &PREPARED_PUBKEY)
    } else {
        if accounts.len() != 1 {
            return Err(EntryProgramError::InvalidArgument);
        }
        let mut accounts_iter = accounts.iter();
        let prepared_account = next_account_info(&mut accounts_iter)
            .map_err(|_| EntryProgramError::NotEnoughAccountKeys)?;
        if prepared_account.owner != program_id {
            return Err(EntryProgramError::IncorrectProgramId);
        }
        if prepared_account.is_writable {
            return Err(EntryProgramError::InvalidArgument);
        }
        let prepared_data = prepared_account.try_borrow_data()?;
        let prepared_account = Falcon512PreparedPubkeyAccount::try_from_slice(&prepared_data)
            .map_err(map_falcon_error)?;
        instruction
            .signature()
            .verify_with_prepared(instruction.message(), prepared_account.prepared_pubkey())
    };

    if verified {
        Ok(())
    } else {
        Err(EntryProgramError::Custom(ERR_VERIFY_FAILED))
    }
}
