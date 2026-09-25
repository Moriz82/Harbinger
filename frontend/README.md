# Harbinger frontend

The Vite app is the local Harbinger evidence desk. It uses same-origin `fetch` calls and the API contract in the approved plan. It does not ship fixture data or scanner/model integrations.

```sh
npm ci
npm run dev
npm test
npm run typecheck
npm run build
```

Hash navigation keeps the five working areas linkable: map, imports, findings, evidence, and encrypted transfer. The map and asset table share selection state. Finding edits keep unsaved text in memory, warn before unload, and can be saved to a local JSON draft file. SSE change/reset events refresh lists without overwriting a dirty editor.

## Dependency inventory

See [the exact frontend inventory](THIRD-PARTY.md).
