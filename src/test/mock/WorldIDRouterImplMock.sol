// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {WorldIDRouterImplV1} from "../../WorldIDRouterImplV1.sol";

/// @title WorldID Router Implementation Mock
/// @author Worldcoin
contract WorldIDRouterImplMock is WorldIDRouterImplV1 {
    uint32 internal _someMoreData;

    constructor() {
        _disableInitializers();
    }

    /// @notice Used to initialize the new things in the upgraded contract.
    function initialize(uint32 data) public virtual reinitializer(2) {
        _someMoreData = data;
    }

    /// @notice Obtains the value of `someMoreData`.
    function someMoreData() public view returns (uint32) {
        return _someMoreData;
    }
}
