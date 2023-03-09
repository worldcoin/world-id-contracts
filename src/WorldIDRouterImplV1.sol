// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {WorldIDImpl} from "./abstract/WorldIDImpl.sol";

/// @title WorldID Router Implementation Version 1
/// @author Worldcoin
/// @notice A router component that can dispatch group numbers to the correct identity manager
///         implementation.
/// @dev This is the implementation delegated to by a proxy.
contract WorldIDRouterImplV1 is WorldIDImpl {
    ///////////////////////////////////////////////////////////////////////////////
    ///                   A NOTE ON IMPLEMENTATION CONTRACTS                    ///
    ///////////////////////////////////////////////////////////////////////////////

    // This contract is designed explicitly to operate from behind a proxy contract. As a result,
    // there are a few important implementation considerations:
    //
    // - All updates made after deploying a given version of the implementation should inherit from
    //   the latest version of the implementation. This prevents storage clashes.
    // - All functions that are less access-restricted than `private` should be marked `virtual` in
    //   order to enable the fixing of bugs in the existing interface.
    // - Any function that reads from or modifies state (i.e. is not marked `pure`) must be
    //   annotated with the `onlyProxy` and `onlyInitialized` modifiers. This ensures that it can
    //   only be called when it has access to the data in the proxy, otherwise results are likely to
    //   be nonsensical.
    // - This contract deals with important data for the WorldID system. Ensure that all newly-added
    //   functionality is carefully access controlled using `onlyOwner`, or a more granular access
    //   mechanism.
    // - Do not assign any contract-level variables at the definition site unless they are
    //   `constant`.
    //
    // Additionally, the following notes apply:
    //
    // - Initialisation and ownership management are not protected behind `onlyProxy` intentionally.
    //   This ensures that the contract can safely be disposed of after it is no longer used.
    // - Carefully consider what data recovery options are presented as new functionality is added.
    //   Care must be taken to ensure that a migration plan can exist for cases where upgrades
    //   cannot recover from an issue or vulnerability.

    ///////////////////////////////////////////////////////////////////////////////
    ///                    !!!!! DATA: DO NOT REORDER !!!!!                     ///
    ///////////////////////////////////////////////////////////////////////////////

    /// The default size of the internal routing table.
    uint256 internal constant DEFAULT_ROUTING_TABLE_SIZE = 10;

    /// How much the routing table grows when it runs out of space.
    uint256 internal constant DEFAULT_ROUTING_TABLE_GROWTH = 5;

    /// The null address.
    address internal constant NULL_ADDRESS = address(0x0);

    /// The routing table used to dispatch from groups to addresses.
    address[] internal routingTable;

    /// The number of groups currently set in the routing table.
    uint256 internal _groupCount;

    ///////////////////////////////////////////////////////////////////////////////
    ///                                  ERRORS                                 ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice An error raised when routing is requested for a group that does not exist.
    ///
    /// @param groupId The group identifier that was requested but does not exist.
    error NoSuchGroup(uint256 groupId);

    /// @notice An error raised when an attempt is made to add a group that already exists in the
    ///         router.
    ///
    /// @param groupId The group identifier that is duplicated.
    error DuplicateGroup(uint256 groupId);

    /// @notice An error raised when an attempt is made to add a group that is not sequentially next
    ///         in the group order.
    ///
    /// @param groupId The group identifier that is duplicated.
    error NonSequentialGroup(uint256 groupId);

    /// @notice The requested group has been disabled.
    error GroupDisabled();

    ///////////////////////////////////////////////////////////////////////////////
    ///                             INITIALIZATION                              ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Constructs the contract.
    constructor() {
        // When called in the constructor, this is called in the context of the implementation and
        // not the proxy. Calling this thereby ensures that the contract cannot be spuriously
        // initialized on its own.
        _disableInitializers();
    }

    /// @notice Initializes the contract.
    /// @dev Must be called exactly once.
    /// @dev This is marked `reinitializer()` to allow for updated initialisation steps when working
    ///      with upgrades based upon this contract. Be aware that there are only 256 (zero-indexed)
    ///      initialisations allowed, so decide carefully when to use them. Many cases can safely be
    ///      replaced by use of setters.
    ///
    /// @param initialGroupIdentityManager The address of the identity manager to be used for the
    ///        initial group (group ID 0) when instantiating the router.
    ///
    /// @custom:reverts string If called more than once at the same initalisation number.
    function initialize(address initialGroupIdentityManager) public reinitializer(1) {
        // Initialize the sub-contracts.
        __delegateInit();

        // Now we can perform our own internal initialisation.
        routingTable = new address[](DEFAULT_ROUTING_TABLE_SIZE);
        routingTable[0] = initialGroupIdentityManager;
        _groupCount = 1;

        // Mark the contract as initialized.
        __setInitialized();
    }

    /// @notice Responsible for initialising all of the supertypes of this contract.
    /// @dev Must be called exactly once.
    /// @dev When adding new superclasses, ensure that any initialization that they need to perform
    ///      is accounted for here.
    ///
    /// @custom:reverts string If called more than once.
    function __delegateInit() internal virtual onlyInitializing {
        __Ownable_init();
        __UUPSUpgradeable_init();
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                                 ROUTING                                 ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Gets the route for the provided group number.
    ///
    /// @param groupNumber The number of the group to get the route for.
    ///
    /// @return target The target address for the group number.
    ///
    /// @custom:reverts NoSuchGroup If the requested `groupNumber` does not exist.
    /// @custom:reverts GroupDisabled If the group has been disabled.
    function routeFor(uint256 groupNumber)
        public
        view
        onlyProxy
        onlyInitialized
        returns (address target)
    {
        // We want to revert if the group does not exist.
        if (groupNumber >= groupCount()) {
            revert NoSuchGroup(groupNumber);
        }

        // If there is no valid route for a given group we also revert.
        if (routingTable[groupNumber] == NULL_ADDRESS) {
            revert GroupDisabled();
        }

        // With preconditions checked we can return the route.
        return routingTable[groupNumber];
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                             GROUP MANAGEMENT                            ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Adds a group to the router.
    /// @dev It is perfectly valid to add a group to be disabled.
    /// @dev While it reverts if the group identifier is not sequential, this is due to the fact
    ///      that group identifiers are allocated externally. As a result, they cannot just be
    ///      allocated by the router.
    ///
    /// @param groupId The identifier for the new group.
    /// @param groupIdentityManager The address of the identity manager instance to be used for the
    ///        group. If this is set to the null address the group is disabled.
    ///
    /// @custom:reverts DuplicateGroup If the `groupId` already exists in the routing table.
    /// @custom:reverts NonSequentialGroup If the `groupId` is not the sequentially next group based
    ///                 on the known groups.
    function addGroup(uint256 groupId, address groupIdentityManager)
        public
        onlyProxy
        onlyInitialized
        onlyOwner
    {
        // Duplicate groups cannot be added.
        if (groupId < groupCount()) {
            revert DuplicateGroup(groupId);
        }

        // Groups should be added sequentially.
        if (groupId != nextGroupId()) {
            revert NonSequentialGroup(groupId);
        }

        // Insert the entry into the routing table.
        insertNewTableEntry(groupId, groupIdentityManager);
    }

    /// @notice Updates the target address for a group in the router.
    /// @dev It is perfectly valid to add a group to be disabled.
    ///
    /// @param groupId The identitifier for the group to have its target address updated.
    /// @param newTargetAddress The new target address for the group in routing. If this is set to
    ///        the null address the group will be disabled.
    ///
    /// @return oldTarget The old target address for the group.
    ///
    /// @custom:reverts NoSuchGroup If the target group does not exist to be updated.
    function updateGroup(uint256 groupId, address newTargetAddress)
        public
        onlyProxy
        onlyInitialized
        onlyOwner
        returns (address oldTarget)
    {
        // It is not possible to update a non-existent group.
        if (groupId >= groupCount()) {
            revert NoSuchGroup(groupId);
        }

        oldTarget = routingTable[groupId];
        routingTable[groupId] = newTargetAddress;
    }

    /// @notice Disables the target group in the router.
    ///
    /// @param groupId The identifier for the group to be disabled.
    ///
    /// @return oldTarget The old target address for the group.
    ///
    /// @custom:reverts NoSuchGroup If the target group does not exist to be disabled.
    function disableGroup(uint256 groupId)
        public
        onlyProxy
        onlyInitialized
        onlyOwner
        returns (address oldTarget)
    {
        return updateGroup(groupId, NULL_ADDRESS);
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                              DATA QUERYING                              ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Gets the number of groups in the routing table.
    ///
    /// @return count The number of groups in the table.
    function groupCount() public view onlyProxy onlyInitialized returns (uint256 count) {
        return _groupCount;
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                            INTERNAL FUNCTIONS                           ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Inserts the `targetAddress` into the routing table for the provided `groupId`.
    /// @dev Grows the routing table if necessary to accommodate the provided entry.
    ///
    /// @param groupId The group identifier to add to the routing table.
    /// @param targetAddress The address to be routed to for the provided `groupId`.
    function insertNewTableEntry(uint256 groupId, address targetAddress)
        internal
        onlyProxy
        onlyInitialized
    {
        while (groupId >= routingTable.length) {
            uint256 existingTableLength = routingTable.length;
            address[] memory newRoutingTable =
                new address[](existingTableLength + DEFAULT_ROUTING_TABLE_GROWTH);

            for (uint256 i = 0; i < existingTableLength; ++i) {
                newRoutingTable[i] = routingTable[i];
            }

            routingTable = newRoutingTable;
        }

        routingTable[groupId] = targetAddress;
        _groupCount++;
    }

    /// @notice Gets the group identifier for the group with the highest group identifier known to
    ///         the router.
    ///
    /// @return groupId The highest group identifier known.
    function nextGroupId() internal view onlyProxy onlyInitialized returns (uint256 groupId) {
        return _groupCount;
    }
}
