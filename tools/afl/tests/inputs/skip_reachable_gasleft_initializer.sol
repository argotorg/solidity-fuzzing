// Regression input: gasleft() in a state variable initializer, which no function or modifier body contains but the
// constructor runs.
contract C {
    uint public x = gasleft();
}
