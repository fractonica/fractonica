# fractonica-client-content

Private local filesystem storage for immutable Fractonica media.

Bytes are written only to private temporary or partial files. A complete file
is checked against its signed `ContentDescriptor`, flushed, and atomically
published under its SHA-256 content ID. Interrupted downloads resume from the
durable partial-file length. Failed length or digest checks never expose a blob.

Committed paths and staging paths are derived only from canonical digests;
filenames from records never become paths. Symlinked files are refused. On
Unix, directories and files are restricted to `0700` and `0600`. Verified
immutable files are cached by stable metadata so multi-chunk uploads do not
rehash a large file for every chunk; any fingerprint change forces complete
verification.

The store does not decide which peer needs a resource. The synchronization
layer performs bounded tus upload and HTTP range-download steps and persists
scheduling separately.

