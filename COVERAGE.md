# Coverage report generation for isoltest/fuzzer

## 0. Build with coverage (separate tree)
`build/` cannot be used: the top-level CMakeLists.txt forces `TESTS=OFF`, so it has no isoltest, and it has no
coverage flags. Build the solidity submodule on its own instead:
```
cmake -S solidity -B build_cov -DCMAKE_BUILD_TYPE=Release -DCOVERAGE=ON
make -C build_cov -j$(nproc) isoltest solc
```

## 1. Reset counters (clean slate)
```
lcov --zerocounters --directory build_cov
```

## 2. Run isoltest (or solc many times, or both — they all accumulate)
```
./build_cov/test/tools/isoltest --testpath solidity/test --vm build/evmone-build/lib/libevmone.so \
  --accept-updates --no-smt
```

## 3. Capture & generate HTML
```
lcov --capture --directory build_cov \
  --output-file coverage.info --ignore-errors inconsistent
lcov --remove coverage.info '/usr/*' '*/test/*' '*/deps/*' \
  --output-file coverage_filtered.info --ignore-errors inconsistent
genhtml coverage_filtered.info \
  --output-directory coverage_html --ignore-errors inconsistent
```

Then open coverage_html/index.html.
