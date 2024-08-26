// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Vm} from "forge-std/Vm.sol";
import {Test} from "forge-std/Test.sol";

import "forge-std/console.sol";

/// @title World ID Test
/// @notice Contains test utilities for WorldID.
/// @author Worldcoin
contract WorldIDTest is Test {
    ///////////////////////////////////////////////////////////////////////////////
    ///                                TEST DATA                                ///
    ///////////////////////////////////////////////////////////////////////////////

    Vm internal hevm = Vm(VM_ADDRESS);
    address internal nullAddress = address(0x0);
    address internal thisAddress = address(this);

    ///////////////////////////////////////////////////////////////////////////////
    ///                              TEST UTILITIES                             ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Asserts that making the external call using `callData` on `target` succeeds.
    ///
    /// @param target The target at which to make the call.
    /// @param callData The ABI-encoded call to a function.
    function assertCallSucceedsOn(address target, bytes memory callData) public {
        (bool status,) = target.call(callData);
        assert(status);
    }

    /// @notice Asserts that making the external call using `callData` on `target` succeeds.
    ///
    /// @param target The target at which to make the call.
    /// @param callData The ABI-encoded call to a function.
    /// @param expectedReturnData The expected return data from the function.
    function assertCallSucceedsOn(
        address target,
        bytes memory callData,
        bytes memory expectedReturnData
    ) public {
        (bool status, bytes memory returnData) = target.call(callData);
        assert(status);
        assertEq(expectedReturnData, returnData);
    }

    /// @notice Asserts that making the external call using `callData` on `target` fails.
    ///
    /// @param target The target at which to make the call.
    /// @param callData The ABI-encoded call to a function.
    function assertCallFailsOn(address target, bytes memory callData) public {
        (bool status,) = target.call(callData);
        assert(!status);
    }

    /// @notice Asserts that making the external call using `callData` on `target` fails.
    ///
    /// @param target The target at which to make the call.
    /// @param callData The ABI-encoded call to a function.
    /// @param expectedReturnData The expected return data from the function.
    function assertCallFailsOn(
        address target,
        bytes memory callData,
        bytes memory expectedReturnData
    ) public {
        (bool status, bytes memory returnData) = target.call(callData);
        assert(!status);
        assertEq(expectedReturnData, returnData);
    }

    /// @notice Performs the low-level encoding of the `revert(string)` call's return data.
    /// @dev Equivalent to `abi.encodeWithSignature("Error(string)", reason)`.
    ///
    /// @param reason The string reason for the revert.
    ///
    /// @return data The ABI encoding of the revert.
    function encodeStringRevert(string memory reason) public pure returns (bytes memory data) {
        return abi.encodeWithSignature("Error(string)", reason);
    }
}
