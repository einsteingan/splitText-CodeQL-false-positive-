# CodeQL Finding Review: `js/xss-through-dom` in `vendors.min.js:1431`

**Verdict: False positive. Not exploitable.**

## 1. The finding

CodeQL's `js/xss-through-dom` rule ("DOM text reinterpreted as HTML") flagged
`vendors.min.js:1431`. That line is a bundled, minified copy of **GSAP
(GreenSock) SplitText v3.9.1** — a third-party animation plugin, not
application code. The rule detects a real, general pattern: text read from
the DOM (`.textContent` / `.nodeValue`) later written into an HTML-parsing
sink (`.innerHTML` / `.outerHTML`). Here it correctly spotted that shape, but
did not — and structurally cannot — see the mitigation sitting between the
two.

## 2. Why the flagged path is safe

SplitText copies a text node's content, checks it for a literal `<`, and — if
one is present — swaps every `<` for an inert placeholder token (`{{LT}}`)
*before* it builds any new markup. Only the placeholder-safe string is ever
handed to `outerHTML`. Afterward, the placeholder is converted back to a
literal `<` with a plain `.nodeValue` write, which never triggers HTML
parsing.

Net effect: no character from the original text can reach the `outerHTML`
sink as an actual `<`. Nothing in that text can be parsed into a new element,
regardless of what it contains.

CodeQL's taint tracker has no model for a hand-written `.split("<").join(...)`
substitution as a sanitizer, so it keeps reporting source → sink flow even
though the value is neutralized in between. This is a known limitation of
static analysis on this class of text-processing library code (jQuery,
Splitting.js, and similar libraries trigger the same pattern for the same
reason).

## 3. Empirical proof

Rather than rely on code reading alone, we extracted the exact bytes at
`vendors.min.js:1431` and executed them in a simulated DOM (jsdom), then
attempted the exact attack this rule warns about: place literal HTML markup
inside a text node, then run it through the flagged code path and check
whether any real element gets created.

**Method:** `target.textContent = <payload>` (the normal, safe way user data
reaches the page) → `SplitText.create(target, {...})` (the flagged function)
→ inspect the resulting DOM for real injected elements.

**Payloads tried and results:**

| Payload placed in a text node                     | Real element created? |
|----------------------------------------------------|------------------------|
| `hello <b>PWNED</b> world`                          | No |
| `hi <script>window.__pwned=1</script> bye`          | No |
| `look <img src=x onerror="window.__pwned=2"> here`  | No |

In all three cases, the resulting DOM contained only SplitText's own
character-wrapper `<div>` elements. The injected `<`/`>` characters were
preserved purely as literal, HTML-escaped text (they render back out as
`&lt;`/`&gt;` when the DOM is serialized) — never as parsed `<b>`, `<script>`,
or `<img>` elements. `querySelectorAll('b' | 'script' | 'img' | 'svg' |
'iframe')` returned zero matches in every case.

This test is fully reproducible — see "Reproducing this" below.

## 4. Supporting facts

- Version identifies cleanly as GSAP SplitText **3.9.1** (`SplitText.version`
  reads `"3.9.1"`, matching the header comment in the bundle).
- GSAP has one publicly disclosed CVE, **CVE-2020-28478** (prototype
  pollution in the core config-merge logic), fixed in 3.6.0. It is unrelated
  to this code path, and this bundle (3.9.1) already post-dates the fix.
- No public advisory or CVE exists for an XSS in SplitText's text-splitting
  logic.

## 5. Recommendation

- Dismiss the alert as a false positive, referencing this write-up.
- Exclude vendor/minified bundles from future CodeQL JS scans (or scan the
  pre-bundle source instead). Text-splitting/templating libraries like this
  one reliably trigger `js/xss-through-dom` for the reason described above,
  so this will otherwise keep resurfacing on every scan with no action to
  take.

## 6. Reproducing this

Two harnesses are included, testing the same three payloads against two
different sources:

```bash
npm install           # installs jsdom only
node poc_test.js      # runs the payloads against the byte-for-byte extracted
                       # vendor line described above
node poc_test-2.js    # runs the same payloads against a full vendors.min.js
                       # bundle (default: ./vendors.min.js), for confirming
                       # the finding on a real production bundle rather than
                       # a hand-extracted snippet
```

`poc_test-2.js` doesn't rely on a hardcoded line number or a specific
minified signature (e.g. `SplitText.create=function create`) to find
SplitText, since different builds/minifiers rename internal variables and
may not keep SplitText on its own line or in its own UMD wrapper — in one
real bundle we tested, SplitText shared a single ~250k-character line with
the full GSAP core and other unrelated vendor libraries. Instead it loads
the *entire* bundle into a real jsdom `window` (the same way a browser
`<script>` tag would) and reads the resulting `window.SplitText` global,
however the minifier happened to name things internally. Both scripts print
the text node's `nodeValue` before SplitText runs and the full
`target.innerHTML` after, so the escaping can be inspected visually, and
both concluded: no real elements created in any payload -> NOT exploitable.

Files included:
- `splittext_from_vendor.js` — byte-for-byte extract of `vendors.min.js:1431`
- `poc_test.js` — test harness against `splittext_from_vendor.js`
- `poc_test-2.js` — test harness against a full `vendors.min.js` bundle
- `run_output.txt` — captured output from an actual `poc_test.js` run
