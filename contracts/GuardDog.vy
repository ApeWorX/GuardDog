#pragma version ^0.4.0
"""
@title GuardDog
@license Apache 2.0
@author ApeWorX LTD
@dev Safe Guard for protecting against silent delegatecalls
@notice Can only work for Safes v1.3.0 or above
"""

SAFE: public(immutable(address))
UPGRADE_DELAY: public(immutable(uint256))

# Timestamp that delegatecall to target is allowed
delegatecallAllowedSince: public(HashMap[address, uint256])

# Check guard upgrade (e.g. `setGuard(new_guard: address)` called)
nextGuard: public(address)
guardUpgradeAllowedAt: public(uint256)


event DelegateCallProposed:
    callee: indexed(address)

event DelegateCallRevoked:
    callee: indexed(address)

event GuardUpgradeProposed:
    currentGuard: indexed(address)
    nextGuard: indexed(address)


@deploy
def __init__(safe: address, upgradeDelay: uint256, allowedDelegatecallTargets: DynArray[address, 20]):
    SAFE = safe
    UPGRADE_DELAY = upgradeDelay

    for target: address in allowedDelegatecallTargets:
        self.delegatecallAllowedSince[target] = block.timestamp

    # NOTE: Cache these to prevent bricking the install operation of Guard
    self.nextGuard = self
    self.guardUpgradeAllowedAt = block.timestamp


@pure
@external
def supportsInterface(interfaceId: bytes4) -> bool:
    return (
        interfaceId == 0x01ffc9a7
        or interfaceId == 0xe6d7a83a
    )


# Configuration functions (Must be called by Safe)
@external
def proposeDelegateCallable(target: address):
    assert msg.sender == SAFE.address
    assert self.delegatecallAllowedSince[target] == 0
    self.delegatecallAllowedSince[target] = block.timestamp + UPGRADE_DELAY

    log DelegateCallProposed(target)


@external
def revokeDelegateCallable(target: address):
    assert msg.sender == SAFE.address
    # NOTE: `target` can never be used again
    self.delegatecallAllowedSince[target] = max_value(uint256)

    log DelegateCallRevoked(target)


@external
def proposeGuardUpgrade(nextGuard: address):
    # NOTE: Must be called before attempting upgrade (while Guard is installed)
    assert msg.sender == SAFE.address

    log GuardUpgradeProposed(self.nextGuard, nextGuard)
    self.nextGuard = nextGuard
    self.guardUpgradeAllowedAt = block.timestamp + UPGRADE_DELAY


# Guard functions
@external
def checkTransaction(
    target: address,
    _value: uint256,
    data: Bytes[2**63],
    operation: uint8,  # Operation enum { Call: 0, DelegateCall: 1 }
    safeTxGas: uint256,
    baseGas: uint256,
    gasPrice: uint256,
    gasToken: address,
    refundReceiver: address,
    signatures: Bytes[65535],
    msgSender: address,
):
    if operation == 0:
        # NOTE: Normal operations don't concern us since they cannot modify Safe state
        return

    elif target != SAFE.address:
        # NOTE: Delegate call contracts must be pre-vetted
        assert self.allowedSince[target] >= block.timestamp

    # NOTE: v1.3.0 and after requires explicit migration contract to upgrade `_singleton` slot,
    #       which requires deploying and using a "migrations contract" via the normal delegatecall
    #       timelock we have implemented above. You should always verify the delegatecall target.

    elif abi_decode(
            slice(data, 0, 4),
            # NOTE: Right-pad align to 32 byte boundry for conversion
            0x00000000000000000000000000000000000000000000000000000000,
        ),
        bytes4,
    ) == 0xe19a9dd9:
        # NOTE: Safe called `setGuard(address)` on itself, prevent upgrade without timelock
        nextGuard: address = abi_decode(slice(data, 4, 36), address)
        assert nextGuard == self.nextGuard
        assert block.timestamp >= self.guardUpgradeAllowedAt

    # NOTE: Wallets with Safe support are usually pretty good at showing known issues when
    #       calling a delegatecall against itself, we did not implement this featureset.


# NOTE: This is needed to fit the required interface for a guard
@external
def checkAfterExecution(hash: bytes32, success: bool):
    pass


# NOTE: Don't revert on fallback to avoid issues in case of a Safe upgrade.
#       The expected check method might change and then the Safe would be locked.
@external
def __default__():
    pass
