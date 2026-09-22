# Current browser acceptance

`browser_acceptance.py` tests the built app served on a specified loopback origin with installed Python Playwright and Chromium. It also supports Merlin so that both desks use the same acceptance assertions. No package dependency or backend contract is changed.

The browser loads real HTML, JavaScript and CSS from the application service. It first checks the real, unauthenticated login screen without entering credentials. Subsequent API requests, including login, are redirected to an ephemeral loopback fixture with synthetic records. This tests the rendered UI and form contract, not live authentication or persistence. Unknown fixture endpoints fail the run. External requests fail the run and are blocked. No application state is written, no app process is stopped, and no transfer or delivery is sent.

The fixture uses a native browser `EventSource` and an actual HTTP event stream. Closing that stream tests disconnection messaging, disabled save/sign-out controls, retained local text, and absence of an attempted offline write. This is a controlled fixture connection loss, not a live backend outage rehearsal.

## Run

From the Harbinger checkout, with its local service running:

```sh
python3 acceptance/browser_acceptance.py --app Harbinger --origin http://127.0.0.1:8710 --output acceptance/browser-current
```

From the adjacent Merlin checkout:

```sh
python3 ../Harbinger/acceptance/browser_acceptance.py --app Merlin --origin http://127.0.0.1:8711 --output acceptance/browser-current
```

The runner accepts only `http://127.0.0.1:<port>`. `--chromium` can select an already installed Chromium executable. It exits nonzero when an assertion fails and replaces a prior result with `incomplete` before starting so an interrupted run cannot leave a prior passing result presented as current.

## Evidence and boundaries

`browser-current/RESULTS.json` records the run time, Chromium/Playwright versions, runner hash, served asset hashes, each assertion, network/console errors, and a capture manifest. Each PNG records synthetic role, route, fixture revision, viewport, actual dimensions and SHA-256. Captures are viewport images, not full-page images. Review the manifest's `status`; a screenshot alone is not a passing result.

The final 2026-09-22 run passed all three viewport cases with zero browser, network or HTTP errors. All nine current Harbinger captures were visually reviewed, and their hashes and dimensions were verified. The served JS/CSS hashes also match the local `frontend/dist` bytes. Some editor captures are scrolled to the edited field; they show the viewport at that interaction point.

The 2026-09-22 run covers:

| Check | Automated proof |
| --- | --- |
| 1366 x 768 and 1920 x 1080 | Loaded primary routes, editor and offline state; no page-wide horizontal overflow |
| Login | Real unauthenticated login screen; synthetic form submission and authenticated UI navigation |
| Harbinger reminder | Exactly one visible `report as you go` emphasis element with computed italic style |
| Keyboard | First Tab shows a styled skip link; Enter focuses main; Enter navigates primary links; modal initial focus, forward/backward wrap, Escape and restored trigger focus |
| Map alternative | Keyboard selection of a synthetic isolated node updates the inspector |
| Reduced motion | Browser preference recognized; no running animations or nonzero computed transition durations on the home view |
| Accessibility structure | Chromium accessibility tree has one main landmark and named controls on loaded routes/editor |
| Connection loss | Actual native fixture stream closes; truthful offline banner, local text retention, disabled writes and no attempted offline write |
| Diagnostics | Online page exceptions, console errors, failed requests, HTTP errors, external requests and missing fixtures fail the run |

683 x 384 is an additional compact layout check, approximating the CSS viewport available at 200% zoom on a 1366 x 768 display. It does **not** apply browser zoom. Actual 200% browser zoom remains manual: set browser zoom to 200%, navigate every primary route and the editor, and verify reachable controls, readable content and no page-wide horizontal scrolling.

Accessibility-tree inspection does **not** run a screen reader. Screen-reader speech, reading order, status announcements, modal announcements and practical navigation remain manual acceptance. No WCAG conformance claim is made by this runner.

## Existing tools and licenses

No dependencies were installed or added. This run reused Python 3.14, Playwright **1.62.0** (installed distribution metadata: **Apache-2.0**) and Chromium **152.0.7977.75** (Chromium BSD-style project license plus bundled component licenses available in `chrome://credits`). Python's standard library uses the PSF license. These are acceptance tools only; app dependency inventories remain in `frontend/THIRD-PARTY.md`.
