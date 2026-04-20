{
    // Deploy a sub-contract via create2 that writes to storage.
    // Sub-contract init code: PUSH1 7, PUSH1 0, SSTORE, STOP
    // = 0x6007600055 00 (6 bytes)
    // The sub-contract's storage should have slot 0 = 7.
    // Different optimization of the outer code may produce different create2 addresses,
    // but storage values should match.

    // Store init code in memory (left-aligned in 32-byte word)
    // 0x600760005500 = 6 bytes, shifted left by 26 bytes (208 bits)
    mstore(0, shl(208, 0x600760005500))

    // create2(value=0, offset=0, size=6, salt=0x42)
    let addr := create2(0, 0, 6, 0x42)

    // Write our own storage to mark success
    sstore(0, addr)

    mstore(0, 1)
    return(0, 32)
}
