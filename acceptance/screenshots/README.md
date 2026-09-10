# Synthetic screenshot capture manifest

Capture only synthetic workspace data. Do not capture client records, source artifacts, keys, tokens, or browser session values.

For each capture, create a manifest entry with:

```text
capture_id:
application: Harbinger or Merlin
route:
viewport:
image_dimensions: actual PNG width and height
role:
browser_zoom: record the actual browser zoom, or unknown
fixture: synthetic fixture name and revision
operator:
captured_at_utc:
file: relative PNG path
sha256:
notes: visible state and any limitation
```

Use a repeatable viewport and fixture. Record the route, role, and state that the capture proves. Store PNG files in this directory only after review.

The checked-in set contains four historical synthetic images: map and findings at recorded browser viewports of 1366 x 768 and 1920 x 1080. The PNGs are taller than those viewports; `image_dimensions` records their actual pixel sizes. All four hashes and dimensions were verified during this remediation, and the images were visually inspected. Their filenames and viewport fields are retained as the original capture metadata.

Eight current synthetic captures supplement the historical set. They show the current overview at 1366 x 768, 1920 x 1080, and 683 x 384; graph and readiness failures; an isolated node selected through the keyboard; an image fallback; and conflict details retained after the exact local app container stopped. The automated run also checked page-wide horizontal overflow, console and page errors, first-tab focus, the italic reminder, reduced-motion preference recognition, graph and readiness recovery, disabled offline writes, and the app's healthy restart.

Headless Chromium did not apply its browser zoom shortcut. The 683 x 384 capture proves only the compact layout. Actual 200 percent browser zoom and screen-reader output still require browser acceptance.
