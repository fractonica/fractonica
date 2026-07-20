# @fractonica/client

Strict TypeScript types and HTTP access for the Fractonica node's client
projections.

The package can:

- page through record, event, tag, and profile projections with complete
  keyset cursors;
- read aggregate client statistics;
- fetch immutable signed operations;
- submit an operation that has already been signed by trusted native code;
- preserve structured node problem codes and reject unexpected response
  fields.

It cannot create signatures and must not receive actor private keys. A desktop
webview should obtain signed operations from Tauri commands backed by
`fractonica-client`; iOS should use its native bridge. Calling `submit` is an
outbox delivery step, not the local save operation.

```ts
import { FractonicaNodeClient } from "@fractonica/client";

const node = new FractonicaNodeClient("http://127.0.0.1:8789");
const page = await node.listRecords(spaceId, { limit: 50 });

if (page.nextCursor) {
  const older = await node.listRecords(spaceId, {
    limit: 50,
    cursor: page.nextCursor,
  });
}
```

The default timeout is five seconds. Pass an `AbortSignal` for navigation or
view-lifetime cancellation. A paired remote transport may inject its bearer
credential and `fetch` implementation through `NodeClientOptions`.

