# First cheap build: retained compile failure

Build01 exited101 before any unit test, full synthesis, setup or proof. Rust
E0716 identified the conditional temporary array passed by reference to
`path_root` in `fixture.rs`. The new fixture constructor now binds an owned
`pool_notes` vector before borrowing its slice. No circuit or wire rule changes.
The original source snapshot/log/result are retained. Build02 uses its own
source snapshot and output identity; it is a compile retry, not a repeated
semantic experiment. The exact reused SHA gadget's unused-import warning is
retained without changing that licensed source.
