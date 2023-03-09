# WorldID Router

While there are currently no plans to add multiple groups to WorldID, doing so would demand a new
pair of [signup sequencer](https://github.com/worldcoin/signup-sequencer) and identity manager for
each group. While the sequencer is easily able to work directly with a given identity manager
instance, this becomes far more complicated for other clients of WorldID.

To that end, the WorldID router exists to provide a trusted place where clients of WorldID can turn
their group numbers into the target address for the associated identity manager instance. The router
is intended to be used as follows:

1. The router should be deployed with the address of the initial group 0 identity manager.
2. Clients who want to interact with the WorldID identity managers should encode the address of the
   _router_ into their application.
3. When wanting to query WorldID they should first ask the router for the address of the manager for
   the appropriate group.

This not only simplifies writing client interactions with WorldID, but also simplifies those client
interactions in the face of changes to addresses for identity managers (such as those necessitated
by actioning the [disaster recovery plan](./Disaster%20Recovery%20Plan.md)).

## Signup Sequencer Usage

As a given instance of the sequencer only works with a single group, the signup sequencer can
interact _directly_ with the corresponding WorldID Identity Manager instance deployed on chain.
**Under no circumstances** should the signup sequencer be altered to use the router.
