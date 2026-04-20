{
    // Simple Yul block with storage writes. Should match across all configs.
    let x := 42
    sstore(0, x)
    sstore(1, add(x, 1))
    mstore(0, sload(0))
    return(0, 32)
}
