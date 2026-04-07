# Coverage report generation for isoltest/fuzzer

## 1. Reset counters (clean slate)
```
lcov --zerocounters --directory build
```

## 2. Run isoltest (or solc many times, or both — they all accumulate)
```
./build/test/tools/isoltest --accept-updates --no-smt
```

## 3. Capture & generate HTML
```
lcov --capture --directory build \
  --output-file coverage.info --ignore-errors inconsistent
lcov --remove coverage.info '/usr/*' '*/test/*' '*/deps/*' \
  --output-file coverage_filtered.info --ignore-errors inconsistent
genhtml coverage_filtered.info \
  --output-directory coverage_html --ignore-errors inconsistent
```

Then open coverage_html/index.html.
