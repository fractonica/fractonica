# fractonica-client

`fractonica-client` is Fractonica's platform-neutral operation authoring layer.
It creates signed record, event, tag, and profile operations without knowing
about HTTP, SQLite, UI state, or a particular key store.

The intended native-client sequence is:

1. construct a validated application document;
2. author and sign an operation through `ActorKeyCustody`;
3. commit that exact signed operation to the client's durable local store;
4. update the local projection and return control to the UI;
5. enqueue the operation for asynchronous delivery to any configured nodes.

An edit or tombstone must use an `ObservedEntity` built from every head the
client has observed locally. This preserves concurrent history rather than
silently choosing a server revision. A node accepting or rejecting delivery
does not undo the local commit.

`SoftwareActorKey` is provided for tests and headless agents. Desktop and iOS
applications should implement `ActorKeyCustody` over their reviewed native
key stores so browser/UI code never receives private key bytes.

This crate deliberately does not yet provide local persistence, an outbox,
private-document encryption, resource upload orchestration, or replication.
Those layers consume its signed output without changing it.

