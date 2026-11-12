// Tier 2 of the proof ladder: Node loads both packages through the tree
// rules_js linked and prints the first line of each entry file, which is
// where a patched tarball carries its marker.
const fs = require("fs");

for (const name of ["left-pad", "@tootallnate/once"]) {
  const first = fs.readFileSync(require.resolve(name), "utf8").split("\n")[0];
  console.log(`socket-fixture ${name}: ${first}`);
}
console.log(`socket-fixture left-pad result: ${require("left-pad")("7", 3, "0")}`);
