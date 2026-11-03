# Selected cold release delta

The local rehearsal retains the exact archived e05922ea source. The new cold
release has the same action accounting, slots, sizing and witness/native APIs.
Its explicit changes are:

1. Five formerly unset constants now bind root-selected manifestb440d08f,
   domainbd9a7227, VKdade8f90, builda26f7b49 and selected cold ELF3252c28f.
   Generic nativef6139cea, network19dffcaa and crypto6f65ec20 are unchanged.
2. Newly requested payments reject a target tuple matching ANY recognized own
   historical receipt, including spent receipts. This is forward-creation
   privacy hygiene, not global recipient freshness. Existing accepted duplicate
   claims keep their owner_action_available and backing; no recovery or full
   exit authority is revoked. Fresh-recipient local rehearsal material is
   unchanged by this admission check.
3. One focused historical-target rejection control was added; the unselected
   gate test now explicitly mocks an unset constant, so it remains meaningful
   after selection. README now distinguishes selected software from authorization
   to use actual backups. The original27-control artifact stays historical.

Targeted controls cover the new guard, preserved duplicate actionability and
fail-closed unselected gate. Public wiring separately checks the complete fixed
network source/software selection and imports it before deliberately rejecting
an empty descriptor. No PK, actual owner backup, proof generation, native VM,
RPC or broadcast is required by these checks. Actual cold use still requires
root's confirmed-prefix and fresh-capture release.
