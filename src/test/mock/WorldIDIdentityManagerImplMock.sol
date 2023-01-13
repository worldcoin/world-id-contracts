// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {WorldIDIdentityManagerImplV1} from "../../WorldIDIdentityManagerImplV1.sol";

/// @title WorldID Identity Manager Implementation Mock
/// @author Worldcoin
contract WorldIDIdentityManagerImplMock is WorldIDIdentityManagerImplV1 {
    uint32 public someMoreData;

    /// @notice Used to initialize the new things in the upgraded contract.
    function initializeV2(uint32 data) public virtual reinitializer(2) {
        someMoreData = data;
    }
}
