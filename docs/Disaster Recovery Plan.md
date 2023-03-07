# World ID Identity Manager Disaster Recovery Plan <!-- omit in toc -->

> This plan aims to provide a tool by which otherwise-unfixable failures in Worldcoin's on-chain
> identity management infrastructure can be remedied swiftly and consistently.

**Scope of Recovery:** WorldID Identity Manager  
**Incident Response Team:** Worldcoin Protocol Team  
**Communications Team:** TBC  
**Recovery Time Goal:** 8 working hours

Unfortunately not all potential issues that can occur with the WorldID Identity Manager can be fixed
by a contract upgrade. From vulnerabilities in the upgrade procedure that cannot be fixed with an
upgrade, to data corruption, to issues under active exploit, such situations require a fallback
plan. That plan is this document.

**Note** that where this document discusses a single pair of (signup sequencer, contract), the
deployed reality may involve _multiple such pairs_, all of which need to be handled in the same way.

- [When to Action the Plan](#when-to-action-the-plan)
- [Disaster Recovery Procedure](#disaster-recovery-procedure)
  - [Pause Identity Operations](#pause-identity-operations)
  - [Record Latest Known Good State](#record-latest-known-good-state)
  - [Roll-Back the Signup Sequencer](#roll-back-the-signup-sequencer)
  - [Fix the Problem](#fix-the-problem)
  - [Deploy the New Contract](#deploy-the-new-contract)
  - [Restart Identity Operations](#restart-identity-operations)
- [Post Recovery Actions](#post-recovery-actions)
  - [Post-Mortem](#post-mortem)
  - [DRP Analysis](#drp-analysis)

## When to Action the Plan

This disaster recovery plan is to be executed upon recognition of one of the following
circumstances:

- **An unexploited vulnerability is found** in the existing contract that cannot be fixed by
  deploying an upgrade.
- **Evidence is found of an exploited vulnerability** in the contract, meaning that the contract
  data is suspect.
- **Data corruption occurs** due to developer mistakes or other circumstances.

## Disaster Recovery Procedure

Upon establishing that the migration plan should be used, the following procedure should be
followed:

1. Pause the identity operations as described [here](#pause-identity-operations).
2. Record the latest known correct state as described [here](#record-latest-known-good-state).
3. Put the signup sequencer in a sensible state as described
   [here](#roll-back-the-signup-sequencer).
4. Fix the cause for activating the disaster recovery plan as described [here](#fix-the-problem).
5. Deploy the new contract with the fixes as described [here](#deploy-the-new-contract).
6. Restart identity operations as described [here](#restart-identity-operations).

Each item below contains a quoted block that describes the short set of steps to take. More detail
follows.

### Pause Identity Operations

> 1. [Stop](#pause-identity-operations-task-1) the signup sequencer instance from submitting
>    identity operations to the contract on the chain.
> 2. [Communicate](#pause-identity-operations-task-2) with the community.

While, in an ideal world, it would be possible to stop the contract from responding to these calls,
this plan cannot assume that we have control of the contract at this time. To this end, the stop is
actioned on the side of the _signup sequencer_, thereby stopping it from modifying the mined
identities in the database.

> #### Pause Identity Operations: Task 1
>
> Stop the signup sequencer as follows:
>
> 1. Obtain VPN access to the production cluster from infrastructure.
> 2. Kill the signup sequencer process running on the node.

At the same time, it is exceedingly important to let the community (who may be relying on the
identity manager and its associated signup sequencer) that a problem has occurred.

> #### Pause Identity Operations: Task 2
>
> 1. Update the community, broadly explaining the nature of the problem, the expected time to
>    recovery, and any anticipated impacts on data.
> 2. Send another update if any of these elements change significantly.

### Record Latest Known Good State

> 1. [Establish](#record-state-task-1) what the last known good state is on chain and match it up to
>    the sequencer's database.
> 2. [Record](#record-state-task-2) this state (the last inserted identity and the last valid root)
>    carefully for reference.

The kinds of issues that can trigger use of this procedure may involve data corruption on chain.
This means that in order to restore service properly it needs to be very clear what the last known
good state is.

> #### Record State: Task 1
>
> 1. Obtain read access to the production database via the VPN already obtained.
> 2. Finding the latest correct root is situationally dependent.
>    - An obvious method is to identify the block where the issue occurred and pick the last root
>      from the block _before_ that happened using the `mined_at` column in the database. This will
>      always be safe.
>    - Note that an issue may occur without data-integrity impact for some time, and hence the above
>      option may be overly-conservative.
>    - We call the established root value `lastGoodRoot`.
> 3. Find the row in the signup sequencer database that corresponds to the last correct root on
>    chain (`lastGoodRoot` found above).
>
> ```sql
> SELECT (root, last_identity, status, created_at, mined_at) -- Select all columns
> FROM root_history                                          -- From the root history table
> WHERE root = lastGoodRoot;                                 -- In rows that match the root value
> ```
>
> 3. Find the last identity inserted as part of the root returned from the above.
>
> ```sql
> SELECT (commitment, leaf_index, status) -- Select all columns
> FROM identities                         -- From the identities table
> WHERE commitment = last_identity;       -- In rows where commitment matches the last_identity from
>                                         -- the previous query
> ```

This gives us the last known good state that the contract was in, and hence the point from which any
data restoration effort needs to begin.

> #### Record State: Task 2
>
> Record this state as:
>
> - **A row in the identities table** of the signup sequencer database; in particular, this is the
>   last known identity where `status == "mined"` that is known to have been correctly submitted on
>   chain.
> - **A row in the roots table** of the signup sequencer database; in particular, this is the last
>   known root where `status == "mined"` that is known to have been correctly submitted on chain.

Once this is done you can be assured that all of the necessary state is available for restoring the
operation of the contract on chain. Make sure to keep this data handy, as it will be necessary for
multiple future steps.

### Roll-Back the Signup Sequencer

> 1. Obtain write access to the production database from the infrastructure team.
> 2. [Back up](#roll-back-task-2) the identities and root history tables.
> 3. [Roll back](#roll-back-task-3) the signup sequencer database such that any identity or root
>    with `status == "mined"` that is not properly represented on the chain is back in
>    `status == "pending"`.

Unfortunately it is _possible_ that the signup sequencer record the status of identities and roots
as `"mined"` when this is spurious (due to on-chain bugs or corruption). To that end we have to be
able to roll back the database to a state that correctly matches the on-chain state to be restored.

> #### Roll-Back: Task 2
>
> 1. Create a back up of the identities table.
>
> ```sql
> CREATE TABLE identities_backup
> AS (SELECT * from identities);
> ```
>
> 2. Create a back up of the root history table.
>
> ```sql
> CREATE TABLE root_history_backup
> AS (SELECT * from root_history);
> ```

With recent backups to save us in case anything goes wrong it is now time to actually roll back the
tables in the production database to a consistent state.

> #### Roll-Back: Task 3
>
> 1. Roll back the identities table.
>
> ```sql
> UPDATE identities                   -- Update the identities table
> SET status = "pending"              -- To set the status for all identities to pending
> WHERE leaf_index > last_leaf_index; -- If those identities are after the last known good identity
>                                     -- (where last_leaf_index) comes from the row in the identities
>                                     -- table that was found above)
> ```
>
> 2. Roll back the roots table.
>
> ```sql
> UPDATE root_history                 -- Update the root history table
> SET status = "pending",             -- To set the status for all roots to pending
>     mined_at = null                 -- And the mined time to null
> WHERE created_at > last_created_at; -- If those roots are after the last known good root (where
>                                     -- last_created_at comes from the row in the root history table
>                                     -- that was found above)
> ```

Once we have fixed the underlying issue, this ensures that the signup sequencer will correctly
re-submit these identities to the chain once brought back up and configured with the address of the
new contract.

### Fix the Problem

> 1. [Establish](#fix-the-problem-task-1) the root cause that led to the activation of the disaster
>    recovery plan.
> 2. [Produce](#fix-the-problem-task-2) a version of the contract that fixes the root cause.

With such a broad spectrum of potential reasons that the disaster recovery plan could be activated,
it is important to understand exactly what went wrong.

A good way to do this is to start from the initial symptom that led to the recognition of the
problem in the first place. From there, you can continually ask "why" that symptom occurred until
you reach the root cause of the problem. Some potential root causes to consider are:

- A logic bug created by a programmer that went uncaught by testing and on staging. If the faulty
  logic was then deployed to production it could have led to data corruption.
- One of the dependencies used to manage the upgrade process for the identity manager has a flaw in
  it that affects the proxy itself, rather than the implementation.

> #### Fix the Problem: Task 1
>
> 1. Identity the initial symptom that allowed the discovery of the issue.
> 2. Identify the cause of that symptom.
> 3. Repeat until the root cause is discovered.

Once the root cause is established it should be possible to put in place a fix for the issue. The
fix should be the _minimum_ fix necessary to resolve the issue to ensure that recovery is performed
promptly. It is of _extreme_ importance here that the fix be comprehensively tested. An incomplete
fix may well result in needing to perform this procedure again.

> #### Fix the Problem: Task 2
>
> 1. Add tests that fail upon reproducing the issue in the existing contract.
> 2. Fix the issue such that the tests no longer fail.
> 3. Add any additional tests that you can think of around the issue.

With that done, the contract is now ready to be deployed again. This means that the restoration of
service as part of the DRP can begin.

### Deploy the New Contract

> 1. [Deploy](#deploy-task-1) the new version of the contract onto the blockchain, passing the last
>    known good root.
> 2. [Give](#deploy-task-2) ownership of the contract to OpenZeppelin relay.

In circumstances such as these, production is considered to be broken. This means that, while care
must be taken when testing the fix, undue time cannot be spent deploying the fix to staging.

> #### Deploy: Task 1
>
> 1. `make build` to ensure that everything is compiled.
> 2. `make test` to ensure that all the tests pass.
> 3. Obtain the deployment private key from the infrastructre team.
> 4. `make deploy` to start the deployment process.
> 5. Answer `n` to the question about reusing configuration.
> 6. Enter the private key obtained from the infrastructure team.
> 7. Provide `https://polygon-mainnet.g.alchemy.com/v2/ZBjU5pzlBWQQPftvl26hJ4cP1VaBrOGq` as the RPC
>    URL.
> 8. Enable the state bridge.
> 9. Obtain the existing state bridge address.
> 10. Provide the obtained state bridge address when asked.
> 11. Leave the "batch insert verifier" address as blank.
> 12. Set the initial root to the `rootValue` obtained above.
> 13. Enter the tree depth to match that used by the signup sequencer.
> 14. Store the contract addresses in the fields below:
>
> **Batch Verifier Contract Address:**  
> **State Bridge Contract Address:**  
> **WorldID Identity Manager Implementation Address:**  
> **WorldID Identity Manager Address:**

There is now a deployment of the fixed contract in production. Care must be taken to ensure that the
newly-deployed contract has been initialized properly so that it is ready to accept new identity
operations. This may include making calls to functions _other than_ `initialize(...)`. As it
currently stands, no additional calls need to be made, but this may change due to the updates made
while performing the [above](#fix-the-problem) tasks.

> #### Deploy: Task 2
>
> 1. Obtain the OpenZeppelin relay address.
> 2. `make transfer-ownership`
> 3. Answer `n` to the question about reusing configuration.
> 4. Provide the relay address when asked.
> 5. Provide the WorldID identity manager address when asked.

At this stage the deployed contract is now installed behind the OpenZeppelin relay contract. This
means that it is ready for use with the signup sequencer, and hence that identity operations can be
restarted.

### Restart Identity Operations

> 1. Restart identity operations in the signup sequencer.

Work performed in the [step](#roll-back-the-signup-sequencer) above will ensure that the signup
sequencer will restart from the last known good state on chain and continue to submit identities
from that point.

> #### Restart: Task 1
>
> 1. Update the `batching-main-stage.values.yaml` file to hold the relay address for the identity
>    manager as `IDENTITY_MANAGER_ADDRESS`. This is the contract address obtained above.
> 2. Push to `batching/main` to trigger a deploy.
> 3. Approve the deploy to production via Datadog.

At this point the entire system should be up and running again. It is recommended to perform
extra-close monitoring of the restored system for the next few hours to ensure that nothing
additional goes wrong.

## Post Recovery Actions

Once the recovery steps have been taken, it may be tempted to take a break from the situation and do
something else. Unfortunately it is _highly_ recommended that you conduct both a
[post-mortem](#post-mortem) and an [analysis of the DRP](#drp-analysis) while the process is fresh
in your mind in order to get the best insights.

### Post-Mortem

The post-mortem is an analysis of the following:

- How the issue occurred that required activation of the DRP.
- Why the issue was not caught _before_ the DRP had to be activated.
- How processes can be improved (if at all) to avoid having to use the DRP in similar situations in
  the future.
- Whether such risks can be mitigated for the future.

### DRP Analysis

The DRP analysis aims to determine what worked well and what needs improvement with regards to the
disaster recovery plan. As part of the process you should identitfy at least the following:

- What worked well in the plan.
- What did not work well or was difficult.
- What friction points delayed the disaster recovery response.
- How the plan can be improved to fix the difficulties and minimise friction in future incidents.
