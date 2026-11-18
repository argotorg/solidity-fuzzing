// Regression input: the isoltest constructor line sends value to a library; IR creation code rejects it, legacy
// accepts it. Found by a viair campaign (2026-11-18).
library test {
    function f(bytes storage) internal pure {}
}
// ----// constructor(), 23 wei ->
