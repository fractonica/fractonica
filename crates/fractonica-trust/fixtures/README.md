# Fractonica trust conformance fixtures

`operation-v2.json` is generated from a fixed, non-secret Ed25519 seed and is
normative for the byte-level protocol. Implementations must reproduce every
identifier, canonical CBOR payload byte, SHA-256 operation identifier,
signature, and tagged COSE_Sign1 byte exactly.

The fixture key is test material only and must never be used as an identity.
The signed payload is the fixed CBOR array:

1. domain text (`org.fractonica.operation.v2`);
2. protocol version (`2`);
3. 32-byte space ID;
4. 32-byte actor Ed25519 public key;
5. 16-byte UUID entity ID;
6. schema text;
7. strictly ascending array of 32-byte causal operation digests;
8. strictly ascending array of 32-byte authorization-grant operation digests;
9. non-negative Unix timestamp in milliseconds;
10. 16-byte nonce;
11. caller-supplied deterministic CBOR body.

The exact protected COSE header is `{1: -8}` (`a10127`), the unprotected map is
empty, and external AAD is the empty byte string.
