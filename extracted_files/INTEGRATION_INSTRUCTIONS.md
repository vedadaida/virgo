USE THESE FILES EXACTLY AS PROVIDED. Do not redesign, restyle, or regenerate the markup/CSS in Landing.jsx, Landing.css, Dashboard.jsx, or Dashboard.css — this is the final, approved design. Only wire them up to real data and routing.

## Files
- `Landing.jsx` + `Landing.css` — the landing/boot page
- `Dashboard.jsx` + `Dashboard.css` — the main app dashboard

Place them in `src/pages/` (or wherever the project's page components live) and import the CSS files exactly as written in each `.jsx` file — don't merge the CSS into a global stylesheet or convert it to CSS modules/Tailwind.

Both components load two Google Fonts: `Press Start 2P` and `Space Mono`. Add this to `index.html` in the `<head>` if it isn't already there:

```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Press+Start+2P&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
```

## Routing
`Landing.jsx` takes a single prop:
```jsx
<Landing onEnter={() => navigate('/dashboard')} />
```
It plays its boot sequence animation, then calls `onEnter` once — wire this to whatever router is already set up in the project (React Router, etc). Do not change the boot sequence timing or steps.

## Dashboard — required data wiring

`Dashboard.jsx` is fully props-driven. It has no hardcoded findings, repos, or stats — you need to supply real data from the backend API. The exact prop shape is documented in a comment block at the top of `Dashboard.jsx`. Read that before wiring it up.

At minimum, wire these:

1. **`repos`** — fetch from `GET /api/repos`, map to `{ id, name, branch, language }`
2. **`findings`** — fetch from `GET /api/repos/:id/findings` (or the "all surfaces" equivalent endpoint), map to the shape in the comment block, including `context`, `aiExplanation`, and `suggestedFix` from the LLM pipeline
3. **`onTriggerScan`** — call `POST /api/scans`, set `scanning={true}` while it's in flight, refetch findings when the scan completes
4. **`onSelectFinding`** — just sets local state (`selectedFindingId`) so the details panel shows the right finding; no API call needed unless you want to lazy-load finding detail
5. **`onFeedback`** — call `POST /api/findings/:id/feedback` with the vote, then update that finding's `feedback` field in state so the UI reflects the active thumbs button

The stat cards (Total/Critical/High/Medium/Low) are computed automatically inside the component from whatever `findings` array you pass in — don't pass separate counts, don't hardcode them.

## Things NOT to change
- Colors, fonts, spacing, border-radius values — all approved as-is
- The severity badge colors (critical=crimson, high=orange, medium=yellow, low=blue)
- The "AI-generated — review before applying" disclaimer text under the AI explanation — do not remove this, it's a deliberate product decision, not placeholder text
- Button hover states (light-color shift, no glow/box-shadow) — this was explicitly requested, don't add glow effects back in
- The active sidebar repo item's solid-fill style — also explicitly requested, don't revert to a subtle border-accent style

## What you SHOULD do
- Replace all data-fetching logic to match the actual backend API routes/schema in this project
- Add loading and error states around the data fetching (the component doesn't currently handle loading/error UI — that's intentionally left for you to add in a way that fits the rest of the app's patterns)
- Add proper TypeScript types if the project uses TypeScript (convert `.jsx` to `.tsx` and type the props based on the comment block)
- Hook up the sidebar's `close-x` button (`onClose` prop) if there's a mobile/collapsible sidebar pattern elsewhere in the project — otherwise it's fine to leave unused
