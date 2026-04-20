{
    // Loop writing to multiple storage slots. Tests optimizer equivalence.
    for { let i := 0 } lt(i, 5) { i := add(i, 1) }
    {
        sstore(i, mul(i, 3))
    }
    mstore(0, sload(2))
    return(0, 32)
}
