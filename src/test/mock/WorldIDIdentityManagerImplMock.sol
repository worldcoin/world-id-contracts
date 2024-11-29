// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {WorldIDIdentityManagerImplV1} from "../../WorldIDIdentityManagerImplV1.sol";

/// @title WorldID Identity Manager Implementation Mock
/// @author Worldcoin
contract WorldIDIdentityManagerImplMock is WorldIDIdentityManagerImplV1 {
    uint32 internal _someMoreData;

    constructor() {
        _disableInitializers();
    }

    /// @notice Used to initialize the new things in the upgraded contract.
    /// The reinitializer value is high not to conflict with subsequent implementations.
    function initialize(uint32 data) public virtual reinitializer(255) {
        _someMoreData = data;
    }

    /// @notice Obtains the value of `someMoreData`.
    function someMoreData() public view returns (uint32) {
        return _someMoreData;
    }
}
