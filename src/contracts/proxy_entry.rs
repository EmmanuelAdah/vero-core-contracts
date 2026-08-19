#![allow(missing_docs)]

use crate::contracts::logic;
use crate::types::{
    BatchCall, ContractError, DataKey, GuardianEntry, RewardStream, Snapshot, SnapshotMeta, Task,
};
use crate::validation::validate_external_address as validate_address;
use crate::DEFAULT_WEIGHT_THRESHOLD;
use crate::{circuit_breaker, drips, events, guardian, reputation, storage, task};
use soroban_sdk::{contract, contractimpl, panic_with_error, Address, BytesN, Env, Vec};

/// The main entrypoint for the Vero Core contract.
///
/// Implements all contract features including voting, task registration,
/// reputation management, token locking, and upgrades.
#[contract]
pub struct VeroContract;

#[contractimpl]
impl VeroContract {
    /// Initializes the Vero Core contract with foundational settings.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The address of the initial contract administrator.
    /// * `token` - The address of the token used for locking.
    /// * `lock_threshold` - The minimum token balance required to lock for guardian status.
    ///
    /// # Returns
    /// * `Ok(())` on successful initialization.
    ///
    /// # Errors
    /// * `ContractError::AlreadyInitialized` if the contract is already initialized.
    /// * Propagates validation errors if `admin` or `token` addresses are invalid.
    ///
    /// # Side Effects
    /// * Sets configuration in instance storage (`Initialized`, `Admin`, `TokenAddress`, `LockThreshold`, `Paused`).
    /// * Grants the `Admin` role to the specified `admin` address.
    /// * Sets the contract migration version.
    /// * Extends the TTL of instance storage.
    /// * Emits a `ContractInitialized` event.
    pub fn initialize(
        env: Env,
        admin: Address,
        token: Address,
        lock_threshold: i128,
    ) -> Result<(), ContractError> {
        validate_address(&env, &admin)?;
        validate_address(&env, &token)?;

        if env
            .storage()
            .instance()
            .get::<_, bool>(&DataKey::Initialized)
            .unwrap_or(false)
        {
            return Err(ContractError::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Initialized, &true);
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::TokenAddress, &token);
        env.storage()
            .instance()
            .set(&DataKey::LockThreshold, &lock_threshold);
        env.storage().instance().set(&DataKey::Paused, &false);

        // Grant Admin role to the deployer/initial admin
        let admin_role_key = DataKey::RoleAssignment(admin.clone(), crate::types::Role::Admin);
        env.storage().instance().set(&admin_role_key, &true);

        crate::migrate::set_version(&env, crate::migrate::CURRENT_VERSION);

        env.storage().instance().extend_ttl(100_000, 100_000);
        events::emit_contract_initialized(&env, &admin);
        Ok(())
    }

    /// Retrieves the primary admin address of the contract.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    ///
    /// # Returns
    /// * `Some(Address)` if an admin is set, otherwise `None`.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads from instance storage.
    pub fn get_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Admin)
    }

    /// Toggles the global pause state of the contract.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The address of the admin invoking the toggle.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * `ContractError::NotAuthorized` if the caller lacks the `EmergencyManager` role.
    /// * Propagates address validation errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Inverts and updates the `Paused` state in instance storage.
    /// * Emits a `PauseToggled` event.
    pub fn toggle_pause(env: Env, admin: Address) -> Result<(), ContractError> {
        validate_address(&env, &admin)?;
        crate::contracts::rbac::require_role(&env, &admin, crate::types::Role::EmergencyManager)?;
        let current = env
            .storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false);
        let new_paused = !current;
        env.storage().instance().set(&DataKey::Paused, &new_paused);
        events::emit_pause_toggled(&env, new_paused);
        Ok(())
    }

    /// Explicitly pauses the contract.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The address of the admin invoking the pause.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * `ContractError::NotAuthorized` if the caller lacks the `EmergencyManager` role.
    /// * Propagates address validation errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Sets the `Paused` state to `true` in instance storage.
    /// * Emits a `PauseToggled` event.
    pub fn pause(env: Env, admin: Address) -> Result<(), ContractError> {
        validate_address(&env, &admin)?;
        crate::contracts::rbac::require_role(&env, &admin, crate::types::Role::EmergencyManager)?;
        env.storage().instance().set(&DataKey::Paused, &true);
        events::emit_pause_toggled(&env, true);
        Ok(())
    }

    /// Explicitly unpauses the contract.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The address of the admin invoking the unpause.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * `ContractError::NotAuthorized` if the caller lacks the `EmergencyManager` role.
    /// * Propagates address validation errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Sets the `Paused` state to `false` in instance storage.
    /// * Emits a `PauseToggled` event.
    pub fn unpause(env: Env, admin: Address) -> Result<(), ContractError> {
        validate_address(&env, &admin)?;
        crate::contracts::rbac::require_role(&env, &admin, crate::types::Role::EmergencyManager)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        events::emit_pause_toggled(&env, false);
        Ok(())
    }

    /// Returns the current global pause status.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    ///
    /// # Returns
    /// * `true` if paused, `false` otherwise.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads from instance storage.
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    /// Adds a new guardian to the system.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The address of the administrator making the addition.
    /// * `guardian` - The address of the guardian being added.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * `ContractError::NotAuthorized` if the caller lacks the `GuardianManager` role.
    /// * Propagates address validation and circuit breaker errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Updates guardian records in storage.
    /// * Emits a `GuardianAdded` event.
    pub fn add_guardian(env: Env, admin: Address, guardian: Address) -> Result<(), ContractError> {
        validate_address(&env, &admin)?;
        validate_address(&env, &guardian)?;
        circuit_breaker::require_not_paused(&env)?;
        crate::contracts::rbac::require_role(&env, &admin, crate::types::Role::GuardianManager)?;
        guardian::add_guardian(&env, admin.clone(), guardian.clone())?;
        events::emit_guardian_added(&env, &admin, &guardian);
        Ok(())
    }

    /// Removes an existing guardian from the system.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The address of the administrator making the removal.
    /// * `guardian` - The address of the guardian being removed.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * `ContractError::NotAuthorized` if the caller lacks the `GuardianManager` role.
    /// * Propagates address validation and circuit breaker errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Removes guardian records from storage.
    /// * Emits a `GuardianRemoved` event.
    pub fn remove_guardian(
        env: Env,
        admin: Address,
        guardian: Address,
    ) -> Result<(), ContractError> {
        validate_address(&env, &admin)?;
        validate_address(&env, &guardian)?;
        circuit_breaker::require_not_paused(&env)?;
        crate::contracts::rbac::require_role(&env, &admin, crate::types::Role::GuardianManager)?;
        guardian::remove_guardian(&env, admin.clone(), guardian.clone())?;
        events::emit_guardian_removed(&env, &admin, &guardian);
        Ok(())
    }

    /// Checks if a specified address is an active guardian.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `guardian` - The address to check.
    ///
    /// # Returns
    /// * `true` if the address is an active guardian, `false` otherwise.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads from instance storage.
    pub fn is_guardian(env: Env, guardian: Address) -> bool {
        guardian::is_guardian(&env, &guardian)
    }

    /// Sets the reputation score for a guardian.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The address of the administrator setting the reputation.
    /// * `guardian` - The address of the guardian.
    /// * `score` - The new reputation score to apply.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * `ContractError::NotAuthorized` if the caller lacks the `GuardianManager` role.
    /// * Propagates address validation and circuit breaker errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Updates the reputation score in storage for the given guardian.
    /// * Emits a `ReputationSet` event.
    pub fn set_reputation(
        env: Env,
        admin: Address,
        guardian: Address,
        score: u64,
    ) -> Result<(), ContractError> {
        validate_address(&env, &admin)?;
        validate_address(&env, &guardian)?;
        circuit_breaker::require_not_paused(&env)?;
        crate::contracts::rbac::require_role(&env, &admin, crate::types::Role::GuardianManager)?;
        reputation::set_reputation(&env, admin.clone(), guardian.clone(), score)?;
        events::emit_reputation_set(&env, &admin, &guardian, score);
        Ok(())
    }

    /// Retrieves the stored reputation score of a guardian.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `guardian` - The address of the guardian.
    ///
    /// # Returns
    /// * `Some(u64)` representing the score if found, otherwise `None`.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads from instance storage.
    pub fn get_reputation(env: Env, guardian: Address) -> Option<u64> {
        reputation::get_reputation(&env, &guardian)
    }

    /// Calculates the dynamic voting power of a guardian based on reputation and stake.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `guardian` - The address of the guardian.
    ///
    /// # Returns
    /// * `Some(u64)` representing the voting power, or `None` if calculation fails.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads from instance storage.
    pub fn calculate_voting_power(env: Env, guardian: Address) -> Option<u64> {
        reputation::calculate_voting_power(&env, &guardian)
    }

    /// Locks a specified amount of tokens to gain or maintain guardian status.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `guardian` - The address locking the tokens.
    /// * `amount` - The quantity of tokens to lock.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Propagates validation, logic, and circuit breaker errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `guardian`.
    /// * Transfers tokens from `guardian` to the contract.
    /// * Modifies the guardian's locked balance in storage.
    pub fn lock_tokens(env: Env, guardian: Address, amount: i128) -> Result<(), ContractError> {
        validate_address(&env, &guardian)?;
        logic::lock_tokens(&env, guardian, amount)
    }

    /// Initiates a withdrawal timelock for locked tokens.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `guardian` - The address of the guardian requesting the unlock.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Propagates validation, logic, and circuit breaker errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `guardian`.
    /// * Writes a timelock timestamp to storage.
    pub fn request_unlock(env: Env, guardian: Address) -> Result<(), ContractError> {
        validate_address(&env, &guardian)?;
        logic::request_unlock(&env, guardian)
    }

    /// Withdraws unlocked tokens after the timelock duration has passed.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `guardian` - The address of the guardian executing the withdrawal.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Propagates validation, logic, and circuit breaker errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `guardian`.
    /// * Transfers unlocked tokens from the contract to `guardian`.
    /// * Resets the locked balance and timelock in storage.
    pub fn unlock_tokens(env: Env, guardian: Address) -> Result<(), ContractError> {
        validate_address(&env, &guardian)?;
        logic::unlock_tokens(&env, guardian)
    }

    /// Recovers tokens from the contract in emergency situations.
    ///
    /// Note: This function deliberately bypasses the circuit breaker pause gate
    /// (`require_not_paused`), as it serves as the recovery mechanism of last resort
    /// when normal contract operations are halted or paused. Requires the caller
    /// to hold the `EmergencyManager` role.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The admin orchestrating the recovery.
    /// * `recipient` - The destination address for the recovered funds.
    /// * `amount` - The token amount to recover.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * `ContractError::NotAuthorized` if caller lacks the `EmergencyManager` role.
    /// * Propagates validation and execution errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Transfers the specified token amount to `recipient`.
    pub fn emergency_recover(
        env: Env,
        admin: Address,
        recipient: Address,
        amount: i128,
    ) -> Result<(), ContractError> {
        validate_address(&env, &admin)?;
        validate_address(&env, &recipient)?;
        crate::contracts::rbac::require_role(&env, &admin, crate::types::Role::EmergencyManager)?;
        logic::emergency_recover(&env, admin, recipient, amount)
    }

    /// Resigns an active guardian and recovers their tokens if the timelock has expired.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `guardian` - The address of the guardian intending to resign.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Propagates validation, logic, and circuit breaker errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `guardian`.
    /// * Removes guardian status from storage.
    /// * Transfers locked tokens back to the guardian.
    pub fn resign_guardian(env: Env, guardian: Address) -> Result<(), ContractError> {
        validate_address(&env, &guardian)?;
        logic::resign_guardian(&env, guardian)
    }

    /// Updates the global weight threshold required for task consensus.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The address of the administrator updating the threshold.
    /// * `threshold` - The new weight threshold value.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * `ContractError::NotAuthorized` if caller lacks the `ConfigManager` role.
    /// * Propagates address validation and circuit breaker errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Updates the `WeightThreshold` in instance storage.
    /// * Emits a `ThresholdSet` event.
    pub fn set_weight_threshold(
        env: Env,
        admin: Address,
        threshold: u64,
    ) -> Result<(), ContractError> {
        validate_address(&env, &admin)?;
        circuit_breaker::require_not_paused(&env)?;
        crate::contracts::rbac::require_role(&env, &admin, crate::types::Role::ConfigManager)?;
        env.storage()
            .instance()
            .set(&DataKey::WeightThreshold, &threshold);
        events::emit_threshold_set(&env, &admin, threshold);
        Ok(())
    }

    /// Retrieves the current global weight threshold for consensus.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    ///
    /// # Returns
    /// * A `u64` representing the threshold.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads from instance storage.
    pub fn get_weight_threshold(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::WeightThreshold)
            .unwrap_or(DEFAULT_WEIGHT_THRESHOLD)
    }

    /// Sets the vault address used for executing automated payouts.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The address of the administrator.
    /// * `vault` - The target vault address.
    ///
    /// # Returns
    /// * No return value.
    ///
    /// # Errors
    /// * Panics with `ContractError::InvalidAddress` if `admin` or `vault` are invalid.
    /// * Panics with `ContractError::NotAuthorized` if caller lacks `ConfigManager` role.
    /// * Panics if the circuit breaker is paused.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Updates the `VaultAddress` in instance storage.
    /// * Emits a `VaultSet` event.
    pub fn set_vault_address(env: Env, admin: Address, vault: Address) {
        if validate_address(&env, &admin).is_err() {
            panic_with_error!(env, ContractError::InvalidAddress);
        }
        if validate_address(&env, &vault).is_err() {
            panic_with_error!(env, ContractError::InvalidAddress);
        }
        circuit_breaker::require_not_paused(&env).unwrap();
        // Use try-catch pattern via unwrap since this function has no Result return
        crate::contracts::rbac::require_role(&env, &admin, crate::types::Role::ConfigManager)
            .unwrap();
        env.storage().instance().set(&DataKey::VaultAddress, &vault);
        events::emit_vault_set(&env, &admin, &vault);
    }

    /// Sets the base fee (in basis points) taken from locking/unlocking activities.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The address of the administrator.
    /// * `bps` - The fee rate in basis points (max 1000).
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * `ContractError::NotAuthorized` if caller lacks the `ConfigManager` role.
    /// * `ContractError::InvalidConfig` if `bps` exceeds 1000.
    /// * Propagates validation and circuit breaker errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Updates the `FeeBps` configuration in instance storage.
    pub fn set_fee_bps(env: Env, admin: Address, bps: u32) -> Result<(), ContractError> {
        validate_address(&env, &admin)?;
        circuit_breaker::require_not_paused(&env)?;
        crate::contracts::rbac::require_role(&env, &admin, crate::types::Role::ConfigManager)?;
        if bps > 1000 {
            return Err(ContractError::InvalidConfig);
        }
        env.storage().instance().set(&DataKey::FeeBps, &bps);
        Ok(())
    }

    /// Sets the treasury address that collects generated fees.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The address of the administrator.
    /// * `treasury` - The destination address for fees.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * `ContractError::NotAuthorized` if caller lacks the `ConfigManager` role.
    /// * Propagates validation and circuit breaker errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Updates the `TreasuryAddress` in instance storage.
    pub fn set_treasury_address(
        env: Env,
        admin: Address,
        treasury: Address,
    ) -> Result<(), ContractError> {
        validate_address(&env, &admin)?;
        validate_address(&env, &treasury)?;
        circuit_breaker::require_not_paused(&env)?;
        crate::contracts::rbac::require_role(&env, &admin, crate::types::Role::ConfigManager)?;
        env.storage()
            .instance()
            .set(&DataKey::TreasuryAddress, &treasury);
        Ok(())
    }

    /// Registers a new task to be evaluated by the guardian consensus network.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The address of the administrator creating the task.
    /// * `task_id` - The unique identifier for the new task.
    /// * `min_votes_required` - The minimum raw vote count required to resolve the task.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * `ContractError::NotAuthorized` if caller lacks the `TaskManager` role.
    /// * Propagates validation and circuit breaker errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Writes a new task configuration to active storage.
    pub fn register_task(
        env: Env,
        admin: Address,
        task_id: u64,
        min_votes_required: u32,
    ) -> Result<(), ContractError> {
        validate_address(&env, &admin)?;
        circuit_breaker::require_not_paused(&env)?;
        crate::contracts::rbac::require_role(&env, &admin, crate::types::Role::TaskManager)?;
        let task_ids = soroban_sdk::vec![&env, task_id];
        task::register_tasks(&env, admin, task_ids, min_votes_required)
    }

    /// Cancels an active, ongoing task.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The address of the administrator.
    /// * `task_id` - The identifier of the task being cancelled.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * `ContractError::NotAuthorized` if caller lacks the `TaskManager` role.
    /// * Propagates validation and circuit breaker errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Updates the task's state in storage to mark it as cancelled.
    pub fn cancel_task(env: Env, admin: Address, task_id: u64) -> Result<(), ContractError> {
        validate_address(&env, &admin)?;
        circuit_breaker::require_not_paused(&env)?;
        crate::contracts::rbac::require_role(&env, &admin, crate::types::Role::TaskManager)?;
        task::cancel_task(&env, admin, task_id)
    }

    /// Purge a terminal task (done or cancelled) from contract storage.
    ///
    /// Removes the task struct, its voter list, each individual `Voted` record,
    /// and the task id from the `AllTasks` index. Reduces on-chain state size
    /// and the cost of future `get_snapshot` calls.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The address of the administrator triggering the purge.
    /// * `task_id` - The identifier of the task being purged.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * `ContractError::TaskNotFound` if no task exists.
    /// * `ContractError::TaskNotTerminal` if the task is still active.
    /// * `ContractError::NotAuthorized` if the caller is not the admin / lacks `TaskManager` role.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Iteratively deletes records associated with the task from active storage.
    pub fn purge_task(env: Env, admin: Address, task_id: u64) -> Result<(), ContractError> {
        validate_address(&env, &admin)?;
        circuit_breaker::require_not_paused(&env)?;
        crate::contracts::rbac::require_role(&env, &admin, crate::types::Role::TaskManager)?;
        task::purge_task(&env, admin, task_id)
    }

    /// Submits a vote on a specific active task on behalf of a guardian.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `guardian` - The address of the voting guardian.
    /// * `task_id` - The identifier of the task being voted on.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Propagates validation, logical voting constraints, and circuit breaker errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `guardian`.
    /// * Acquires and releases a reentrancy lock.
    /// * Appends the voter to the task and dynamically adjusts consensus states in storage.
    pub fn vote(env: Env, guardian: Address, task_id: u64) -> Result<(), ContractError> {
        validate_address(&env, &guardian)?;
        logic::process_vote(&env, guardian, task_id)
    }

    /// Submits a batch of votes for multiple tasks within a single transaction.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `guardian` - The address of the voting guardian.
    /// * `task_ids` - A list of task identifiers to vote on.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Propagates validation, logical voting constraints, and circuit breaker errors.
    ///   Reverts the entire batch if one fails.
    ///
    /// # Side Effects
    /// * Requires authentication from `guardian`.
    /// * Acquires and releases a reentrancy lock.
    /// * Mutates consensus state iteratively for each task in the batch.
    pub fn vote_batch(
        env: Env,
        guardian: Address,
        task_ids: Vec<u64>,
    ) -> Result<(), ContractError> {
        validate_address(&env, &guardian)?;
        logic::process_vote_batch(&env, guardian, task_ids)
    }

    /// Retrieves details for an active task.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `task_id` - The identifier of the task.
    ///
    /// # Returns
    /// * `Some(Task)` if found in active storage, otherwise `None`.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads from instance storage.
    pub fn get_task(env: Env, task_id: u64) -> Option<crate::types::Task> {
        task::get_task(&env, task_id)
    }

    /// Archives a resolved, stale task, moving it from active to archived storage.
    ///
    /// Requires the `TaskManager` role. This was previously permissionless;
    /// however, `start_drips_stream` only resolves tasks from active storage
    /// (no archived-storage fallback), so an unauthorized early archive could
    /// permanently block a task's reward stream from ever starting. Gating
    /// this behind `TaskManager`, consistent with `cancel_task`/`purge_task`,
    /// prevents that griefing vector.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The address of the administrator archiving the task.
    /// * `task_id` - The identifier of the task to archive.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * `ContractError::NotAuthorized` if caller lacks `TaskManager` role.
    /// * Propagates validation and circuit breaker errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Transfers task data from active to archived storage buckets.
    /// * Emits a `TaskArchived` event.
    pub fn archive_task(env: Env, admin: Address, task_id: u64) -> Result<(), ContractError> {
        validate_address(&env, &admin)?;
        circuit_breaker::require_not_paused(&env)?;
        crate::contracts::rbac::require_role(&env, &admin, crate::types::Role::TaskManager)?;
        storage::archive_task(&env, task_id)?;
        events::emit_task_archived(&env, task_id);
        Ok(())
    }

    /// Retrieves an archived task from secondary storage.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `task_id` - The identifier of the task.
    ///
    /// # Returns
    /// * `Some(Task)` if found in archived storage, otherwise `None`.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads from archived storage.
    pub fn get_archived_task(env: Env, task_id: u64) -> Option<crate::types::Task> {
        storage::get_archived_task(&env, task_id)
    }

    /// Starts a Drips reward stream targeting a contributor upon task completion.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The address of the administrator.
    /// * `drips_address` - The address of the Drips protocol contract.
    /// * `contributor` - The receiving address.
    /// * `task_id` - The ID of the resolved task triggering the stream.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * `ContractError::NotAuthorized` if caller lacks `TreasuryManager` role.
    /// * Propagates validation and circuit breaker errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Calls into the specified `drips_address` external contract.
    /// * Emits `RewardStreamStarted` or `RewardStreamFailed` event.
    pub fn start_reward_stream(
        env: Env,
        admin: Address,
        drips_address: Address,
        contributor: Address,
        task_id: u64,
    ) -> Result<(), ContractError> {
        validate_address(&env, &admin)?;
        validate_address(&env, &drips_address)?;
        validate_address(&env, &contributor)?;
        circuit_breaker::require_not_paused(&env)?;
        crate::contracts::rbac::require_role(&env, &admin, crate::types::Role::TreasuryManager)?;

        let result = drips::start_drips_stream(&env, drips_address, contributor.clone(), task_id);

        match &result {
            Ok(()) => events::emit_reward_stream_started(&env, task_id, &contributor),
            Err(_) => events::emit_reward_stream_failed(&env, task_id, &contributor),
        }

        result
    }

    /// Retrieves details on a configured reward stream for a task.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `task_id` - The related task identifier.
    ///
    /// # Returns
    /// * `Some(RewardStream)` if active, otherwise `None`.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads from instance storage.
    pub fn get_reward_stream(env: Env, task_id: u64) -> Option<RewardStream> {
        drips::get_reward_stream(&env, task_id)
    }

    /// Report an observed failure to the circuit breaker.
    ///
    /// Reporting stays open to any observer, but every report is now
    /// **authenticated, rate-limited and quota-capped per address**, and the
    /// breaker only auto-pauses once several *independent* reporters agree.
    /// This preserves the "any observer can report" design goal while making it
    /// impossible for a single address to unilaterally pause the contract.
    ///
    /// See [`crate::circuit_breaker`] for the full trust-model decision record.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `reporter` - The address submitting the failure report.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * `InvalidAddress` — reporter is the zero address or the contract itself.
    /// * `UnauthorizedReporter` — trusted-reporters-only mode is enabled and the
    ///   caller is not a guardian / EmergencyManager / Admin.
    /// * `ReportRateLimited` — the caller reported within the cooldown window.
    /// * `ReporterQuotaExceeded` — the caller exhausted its per-window quota.
    ///
    /// # Side Effects
    /// * Requires authentication from `reporter`.
    /// * Mutates failure counters in storage. May trigger global contract pause.
    pub fn record_failure(env: Env, reporter: Address) -> Result<(), ContractError> {
        validate_address(&env, &reporter)?;
        circuit_breaker::record_failure(&env, reporter)
    }

    /// Current cumulative failure count for the active breaker window.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    ///
    /// # Returns
    /// * A `u32` representing the number of failures.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads from instance storage.
    pub fn get_failure_count(env: Env) -> u32 {
        circuit_breaker::failure_count(&env)
    }

    /// Number of reports the given address contributed to the active window.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `reporter` - The address in question.
    ///
    /// # Returns
    /// * A `u32` representing the reporter's specific failure count.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads from instance storage.
    pub fn get_reporter_failure_count(env: Env, reporter: Address) -> u32 {
        circuit_breaker::reporter_count(&env, &reporter)
    }

    /// Distinct addresses that have reported failures in the active window.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    ///
    /// # Returns
    /// * A `Vec<Address>` listing the unique reporters.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads from instance storage.
    pub fn get_failure_reporters(env: Env) -> Vec<Address> {
        circuit_breaker::failure_reporters(&env)
    }

    /// Whether failure reporting is currently restricted to trusted monitors.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    ///
    /// # Returns
    /// * `true` if restricted, `false` otherwise.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads from instance storage.
    pub fn is_trusted_reporters_only(env: Env) -> bool {
        circuit_breaker::trusted_reporters_only(&env)
    }

    /// Restrict (or re-open) failure reporting to trusted monitors — registered
    /// guardians and `EmergencyManager` / `Admin` role holders.
    ///
    /// Intended as an escape hatch if a Sybil flood of reports is ever observed.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The admin applying the restriction.
    /// * `enabled` - Boolean flag representing the desired setting.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * `NotAuthorized` — caller does not hold the `EmergencyManager` role.
    /// * Propagates address validation errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Updates `TrustedReportersOnly` state in storage.
    /// * Emits a `TrustedReportersOnlySet` event.
    pub fn set_trusted_reporters_only(
        env: Env,
        admin: Address,
        enabled: bool,
    ) -> Result<(), ContractError> {
        validate_address(&env, &admin)?;
        crate::contracts::rbac::require_role(&env, &admin, crate::types::Role::EmergencyManager)?;
        circuit_breaker::set_trusted_reporters_only(&env, enabled);
        events::emit_trusted_reporters_only_set(&env, &admin, enabled);
        Ok(())
    }

    /// Resets the circuit breaker and failure counts.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The address of the administrator invoking the reset.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * `ContractError::NotAuthorized` if caller lacks `EmergencyManager` role.
    /// * Propagates address validation errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Clears all failure counters in storage.
    /// * Emits a `CircuitBreakerReset` event.
    pub fn reset_circuit_breaker(env: Env, admin: Address) -> Result<(), ContractError> {
        validate_address(&env, &admin)?;
        crate::contracts::rbac::require_role(&env, &admin, crate::types::Role::EmergencyManager)?;
        circuit_breaker::reset(&env, admin.clone())?;
        events::emit_circuit_breaker_reset(&env, &admin);
        Ok(())
    }

    /// Returns the estimated off-chain gas/instruction cost metric for an operation.
    ///
    /// # Parameters
    /// * `_env` - The execution environment.
    /// * `op` - The operation enum variant to estimate.
    ///
    /// # Returns
    /// * A `u64` representing cost estimates.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * None.
    pub fn get_estimated_cost(_env: Env, op: crate::types::Operation) -> u64 {
        crate::gas::get_estimated_cost(op)
    }

    /// Immediately replace the contract's WASM code. Callable only by the
    /// contract admin.
    ///
    /// Delegates to [`crate::contracts::upgrade`].
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The administrator authorizing the upgrade.
    /// * `new_wasm_hash` - The bytecode hash of the new implementation.
    ///
    /// # Returns
    /// * No return value.
    ///
    /// # Errors
    /// * Panics on validation or authorization failures.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Replaces the contract implementation in the environment ledger.
    pub fn upgrade_contract(env: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        crate::contracts::upgrade::upgrade_contract(env, admin, new_wasm_hash)
    }

    // ─── Multi-sig upgrade management ────────────────────────────────────────
    // Implemented in `crate::contracts::upgrade`; see there for full docs.

    /// Configure the list of authorized upgrade signers and the required quorum.
    ///
    /// Delegates to [`crate::contracts::upgrade`].
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The admin configuring the signers.
    /// * `signers` - A list of addresses representing the signers.
    /// * `threshold` - The quorum requirement.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Propagates authorization and validation errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Updates signer and threshold data in storage.
    pub fn set_upgrade_signers(
        env: Env,
        admin: Address,
        signers: Vec<Address>,
        threshold: u32,
    ) -> Result<(), ContractError> {
        crate::contracts::upgrade::set_upgrade_signers(env, admin, signers, threshold)
    }

    /// Returns the currently configured list of authorized upgrade signers.
    ///
    /// Delegates to [`crate::contracts::upgrade`].
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    ///
    /// # Returns
    /// * A `Vec<Address>` representing the signer list.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads from storage.
    pub fn get_upgrade_signers(env: Env) -> Vec<Address> {
        crate::contracts::upgrade::get_upgrade_signers(env)
    }

    /// Returns the minimum number of upgrade approvals required (quorum).
    ///
    /// Delegates to [`crate::contracts::upgrade`].
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    ///
    /// # Returns
    /// * A `u32` containing the threshold.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads from storage.
    pub fn get_upgrade_threshold(env: Env) -> u32 {
        crate::contracts::upgrade::get_upgrade_threshold(env)
    }

    /// Propose a new upgrade WASM hash as an upgrade signer.
    ///
    /// Delegates to [`crate::contracts::upgrade`].
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `signer` - The address of the proposing signer.
    /// * `new_wasm_hash` - The hash of the proposed contract code.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Propagates authorization and validation errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `signer`.
    /// * Initiates a new upgrade proposal in storage.
    pub fn propose_upgrade(
        env: Env,
        signer: Address,
        new_wasm_hash: BytesN<32>,
    ) -> Result<(), ContractError> {
        crate::contracts::upgrade::propose_upgrade(env, signer, new_wasm_hash)
    }

    /// Approve a pending upgrade as an authorized signer.
    ///
    /// Delegates to [`crate::contracts::upgrade`].
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `signer` - The address of the approving signer.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Propagates authorization and validation errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `signer`.
    /// * Modifies approval states in storage.
    pub fn approve_upgrade(env: Env, signer: Address) -> Result<(), ContractError> {
        crate::contracts::upgrade::approve_upgrade(env, signer)
    }

    /// Execute the pending upgrade once the approval quorum is met.
    ///
    /// Delegates to [`crate::contracts::upgrade`].
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Propagates errors if quorum is not reached.
    ///
    /// # Side Effects
    /// * Triggers a ledger state replacement with the new WASM hash.
    pub fn execute_upgrade(env: Env) -> Result<(), ContractError> {
        crate::contracts::upgrade::execute_upgrade(env)
    }

    /// Cancel a pending upgrade. Only the contract admin may call this.
    ///
    /// Delegates to [`crate::contracts::upgrade`].
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The address of the administrator.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Propagates authorization and validation errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Clears upgrade-related proposal state from storage.
    pub fn cancel_upgrade(env: Env, admin: Address) -> Result<(), ContractError> {
        crate::contracts::upgrade::cancel_upgrade(env, admin)
    }

    /// Builds the full contract snapshot atomically. Reverts with
    /// `SnapshotTooLarge` once any tracked collection (guardians, tasks,
    /// reward streams) exceeds `MAX_SNAPSHOT_COLLECTION_SIZE` — at that point
    /// use `get_snapshot_meta` plus the paginated `*_page` calls instead.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    ///
    /// # Returns
    /// * `Ok(Snapshot)` containing the current complete state.
    ///
    /// # Errors
    /// * `ContractError::SnapshotTooLarge` if the limit is exceeded.
    ///
    /// # Side Effects
    /// * Performs significant reads across all active storage items.
    pub fn get_snapshot(env: Env) -> Result<Snapshot, ContractError> {
        logic::get_snapshot(&env)
    }

    /// Records the current state snapshot to the ledger permanently.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Propagates circuit breaker and snapshot sizing errors.
    ///
    /// # Side Effects
    /// * Writes a bulk snapshot data object to instance storage keyed by timestamp.
    pub fn record_snapshot(env: Env) -> Result<(), ContractError> {
        circuit_breaker::require_not_paused(&env)?;
        logic::record_snapshot(&env)
    }

    /// O(1) snapshot header (paused/admin/thresholds/addresses) plus the
    /// current guardian/task/reward-stream counts. Always safe to call.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    ///
    /// # Returns
    /// * `SnapshotMeta` metadata structure.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Performs lightweight storage reads.
    pub fn get_snapshot_meta(env: Env) -> SnapshotMeta {
        logic::get_snapshot_meta(&env)
    }

    /// Returns a bounded page of guardians (with status + reputation)
    /// starting at `offset`. `limit` is capped server-side regardless of the
    /// value passed in. Reads `O(limit)` entries, not `O(total guardian
    /// count)` — stays cheaply invokable at guardian counts where
    /// `get_snapshot` is capped out entirely.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `offset` - The starting index.
    /// * `limit` - The maximum number of entries to return.
    ///
    /// # Returns
    /// * A `Vec<GuardianEntry>` containing the requested page.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads subset of records from storage.
    pub fn get_guardians_page(env: Env, offset: u32, limit: u32) -> Vec<GuardianEntry> {
        logic::get_guardians_page(&env, offset, limit)
    }

    /// Returns a bounded page of tasks starting at `offset`. Reads `O(limit)`
    /// entries, not `O(total task count)`.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `offset` - The starting index.
    /// * `limit` - The maximum number of entries to return.
    ///
    /// # Returns
    /// * A `Vec<Task>` containing the requested page.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads subset of records from storage.
    pub fn get_tasks_page(env: Env, offset: u32, limit: u32) -> Vec<Task> {
        logic::get_tasks_page(&env, offset, limit)
    }

    /// Returns a bounded page of reward streams starting at `offset`.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `offset` - The starting index.
    /// * `limit` - The maximum number of entries to return.
    ///
    /// # Returns
    /// * A `Vec<RewardStream>` containing the requested page.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads subset of records from storage.
    pub fn get_reward_streams_page(env: Env, offset: u32, limit: u32) -> Vec<RewardStream> {
        logic::get_reward_streams_page(&env, offset, limit)
    }

    /// Returns the entire history of historical snapshot timestamps.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    ///
    /// # Returns
    /// * A `Vec<u64>` of timestamps when snapshots were recorded.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads from storage.
    pub fn get_snapshot_history(env: Env) -> soroban_sdk::Vec<u64> {
        env.storage()
            .instance()
            .get(&DataKey::AllSnapshots)
            .unwrap_or(soroban_sdk::Vec::new(&env))
    }

    /// Retrieves a complete historical snapshot by its exact timestamp.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `timestamp` - The identifier of the historical snapshot.
    ///
    /// # Returns
    /// * `Ok(Snapshot)` if found.
    ///
    /// # Errors
    /// * `ContractError::SnapshotNotFound` if the snapshot doesn't exist.
    ///
    /// # Side Effects
    /// * Reads snapshot object from storage.
    pub fn get_snapshot_at(env: Env, timestamp: u64) -> Result<Snapshot, ContractError> {
        env.storage()
            .instance()
            .get(&DataKey::Snapshot(timestamp))
            .ok_or(ContractError::SnapshotNotFound)
    }

    /// Gets the expiration timestamp for a guardian's ongoing token withdrawal request.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `guardian` - The address of the guardian.
    ///
    /// # Returns
    /// * `Some(u64)` representing the unlock ledger timestamp, otherwise `None`.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads from storage.
    pub fn get_withdrawal_timelock(env: Env, guardian: Address) -> Option<u64> {
        env.storage()
            .instance()
            .get(&DataKey::WithdrawalTimelock(guardian))
    }

    /// Executes multiple diverse contract calls in a single atomic transaction.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `calls` - A vector of configured `BatchCall` variants representing each action.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Propagates the respective errors of any failing sub-call, reverting the entire batch.
    ///
    /// # Side Effects
    /// * Iterates through `calls` and executes each corresponding function. Side effects match the individual functions called (e.g., auth checks, storage writes, events).
    pub fn batch_execute(
        env: Env,
        calls: soroban_sdk::Vec<BatchCall>,
    ) -> Result<(), ContractError> {
        for call in calls.iter() {
            match call {
                BatchCall::RegisterTask(admin, task_id, min_votes_required) => {
                    Self::register_task(env.clone(), admin, task_id, min_votes_required)?
                }
                BatchCall::CancelTask(admin, task_id) => {
                    Self::cancel_task(env.clone(), admin, task_id)?
                }
                BatchCall::Vote(guardian, task_id) => Self::vote(env.clone(), guardian, task_id)?,
                BatchCall::AddGuardian(admin, guardian) => {
                    Self::add_guardian(env.clone(), admin, guardian)?
                }
                BatchCall::RemoveGuardian(admin, guardian) => {
                    Self::remove_guardian(env.clone(), admin, guardian)?
                }
                BatchCall::SetReputation(admin, guardian, score) => {
                    Self::set_reputation(env.clone(), admin, guardian, score)?
                }
                BatchCall::LockTokens(guardian, amount) => {
                    Self::lock_tokens(env.clone(), guardian, amount)?
                }
                BatchCall::RequestUnlock(guardian) => Self::request_unlock(env.clone(), guardian)?,
                BatchCall::UnlockTokens(guardian) => Self::unlock_tokens(env.clone(), guardian)?,
                BatchCall::ResignGuardian(guardian) => {
                    Self::resign_guardian(env.clone(), guardian)?
                }
                BatchCall::SetWeightThreshold(admin, threshold) => {
                    Self::set_weight_threshold(env.clone(), admin, threshold)?
                }
                BatchCall::SetVaultAddress(admin, vault) => {
                    Self::set_vault_address(env.clone(), admin, vault)
                }
                BatchCall::SetUpgradeSigners(admin, signers, threshold) => {
                    Self::set_upgrade_signers(env.clone(), admin, signers, threshold)?
                }
                BatchCall::ProposeUpgrade(signer, hash) => {
                    Self::propose_upgrade(env.clone(), signer, hash)?
                }
                BatchCall::ApproveUpgrade(signer) => Self::approve_upgrade(env.clone(), signer)?,
                BatchCall::ExecuteUpgrade(_signer) => Self::execute_upgrade(env.clone())?,
                BatchCall::CancelUpgrade(admin) => Self::cancel_upgrade(env.clone(), admin)?,
                BatchCall::StartRewardStream(admin, drips, contributor, task_id) => {
                    Self::start_reward_stream(env.clone(), admin, drips, contributor, task_id)?
                }
                BatchCall::TogglePause(admin) => Self::toggle_pause(env.clone(), admin)?,
                BatchCall::Pause(admin) => Self::pause(env.clone(), admin)?,
                BatchCall::Unpause(admin) => Self::unpause(env.clone(), admin)?,
                BatchCall::RecordFailure(reporter) => Self::record_failure(env.clone(), reporter)?,
                BatchCall::ResetCircuitBreaker(admin) => {
                    Self::reset_circuit_breaker(env.clone(), admin)?;
                }
                BatchCall::EmergencyRecover(admin, recipient, amount) => {
                    Self::emergency_recover(env.clone(), admin, recipient, amount)?
                }
                BatchCall::SetFeeBps(admin, bps) => Self::set_fee_bps(env.clone(), admin, bps)?,
                BatchCall::SetTreasuryAddress(admin, treasury) => {
                    Self::set_treasury_address(env.clone(), admin, treasury)?
                }
            }
        }
        Ok(())
    }

    // ─── Role-based access control ──────────────────────────────────────

    /// Grant a role to a target address. Only callable by Admin role holders.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `caller` - The administrator authorizing the grant.
    /// * `target` - The address receiving the role.
    /// * `role` - The role identifier.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * `ContractError::NotAuthorized` — Caller does not hold the Admin role.
    /// * Propagates validation errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `caller`.
    /// * Creates a RoleAssignment record in storage.
    pub fn grant_role(
        env: Env,
        caller: Address,
        target: Address,
        role: crate::types::Role,
    ) -> Result<(), ContractError> {
        validate_address(&env, &caller)?;
        validate_address(&env, &target)?;
        crate::contracts::rbac::grant_role_internal(&env, &caller, &target, role)
    }

    /// Revoke a role from a target address. Only callable by Admin role holders.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `caller` - The administrator revoking the role.
    /// * `target` - The address losing the role.
    /// * `role` - The role identifier.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * `ContractError::NotAuthorized` — Caller does not hold the Admin role.
    /// * `ContractError::LastAdminRemovalBlocked` — Cannot revoke the last remaining Admin role.
    /// * Propagates validation errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `caller`.
    /// * Removes a RoleAssignment record from storage.
    pub fn revoke_role(
        env: Env,
        caller: Address,
        target: Address,
        role: crate::types::Role,
    ) -> Result<(), ContractError> {
        validate_address(&env, &caller)?;
        validate_address(&env, &target)?;
        crate::contracts::rbac::revoke_role_internal(&env, &caller, &target, role)
    }

    /// Check whether an address holds a specific role.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `address` - The address in question.
    /// * `role` - The role to check.
    ///
    /// # Returns
    /// * `true` if assigned, `false` otherwise.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads from instance storage.
    pub fn has_role(env: Env, address: Address, role: crate::types::Role) -> bool {
        crate::contracts::rbac::has_role(&env, &address, role)
    }

    /// Returns the currently recorded storage version.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    ///
    /// # Returns
    /// * A `u32` identifying the current schema version.
    ///
    /// # Errors
    /// * None.
    ///
    /// # Side Effects
    /// * Reads from storage.
    pub fn get_storage_version(env: Env) -> u32 {
        crate::migrate::get_version(&env)
    }

    /// Run the storage migration to bring the storage schema to the latest version.
    /// Only contract admin can trigger migration.
    ///
    /// # Parameters
    /// * `env` - The execution environment.
    /// * `admin` - The address of the administrator authorizing the migration.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * `ContractError::NotAuthorized` if caller lacks `Admin` role.
    /// * Propagates validation and inner migration logic errors.
    ///
    /// # Side Effects
    /// * Requires authentication from `admin`.
    /// * Alters various state records to comply with updated data schemas.
    pub fn migrate_storage(env: Env, admin: Address) -> Result<(), ContractError> {
        validate_address(&env, &admin)?;
        crate::contracts::rbac::require_role(&env, &admin, crate::types::Role::Admin)?;
        crate::migrate::migrate(&env)
    }

}
