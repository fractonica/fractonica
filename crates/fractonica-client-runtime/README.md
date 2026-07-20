# fractonica-client-runtime

This crate composes Fractonica's native authoring, client SQLite, private
content store, and supervised synchronization layers into one application
service. It is platform-neutral: Tauri, iOS, and headless adapters own its
lifecycle but do not receive private key bytes or database handles.

For the bundled desktop node, bootstrap adopts the node installation's exact
established local-writer identity. It verifies `/api/node`, downloads the
signed genesis and initial capability grant, commits those anchors locally,
and configures the bearer-protected loopback synchronization channel. It never
mints an unrelated actor or constructs replacement authorization.

Create, update, and delete return after the signed operation is committed to
the local client store. The background supervisor performs network and media
work independently. Shutdown is explicit and waits for the worker task.
