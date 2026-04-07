#!/usr/bin/env python3
"""
Check generated Solidity files from sol_proto_ossfuzz_evmone for compilation
errors/warnings and tally language feature usage.

Usage:
    python3 check_sol_proto_files.py <sol_dir> [--solc PATH]

Example:
    python3 check_sol_proto_files.py /path/to/tmp/ --solc ./build-normal/solc/solc
"""

import argparse
import glob
import os
import re
import subprocess
import sys
from collections import Counter


def compile_file(solc, path):
    """Compile a .sol file, return (errors, warnings) as lists of strings."""
    try:
        result = subprocess.run(
            [solc, "--bin", path],
            capture_output=True, text=True, timeout=30
        )
    except subprocess.TimeoutExpired:
        return ["TIMEOUT"], []
    except Exception as e:
        return [f"EXCEPTION: {e}"], []

    errors = []
    warnings = []
    for line in result.stderr.splitlines():
        if "Error:" in line:
            errors.append(line.strip())
        elif "Warning:" in line:
            warnings.append(line.strip())
    # If exit code != 0 and no errors parsed, record raw stderr
    if result.returncode != 0 and not errors:
        errors.append(result.stderr.strip()[:200] if result.stderr.strip() else "Unknown error (nonzero exit)")
    return errors, warnings


def tally_features(content):
    """Count language features present in a Solidity source string."""
    features = Counter()

    # --- Contract structure ---
    features["contracts"] += len(re.findall(r'^contract\s+C\d+', content, re.MULTILINE))
    features["libraries"] += len(re.findall(r'^library\s+', content, re.MULTILINE))
    features["inheritance"] += len(re.findall(r'contract\s+C\d+\s+is\s+', content))

    # --- Functions ---
    features["functions"] += len(re.findall(r'\tfunction\s+f\d+_\d+', content))
    features["free_functions"] += len(re.findall(r'^function\s+ff\d+', content, re.MULTILINE))
    features["constructors"] += len(re.findall(r'\tconstructor\(\)', content))
    features["receive_funcs"] += len(re.findall(r'\treceive\(\)', content))
    features["fallback_funcs"] += len(re.findall(r'\tfallback\(\)', content))

    # --- Visibility / mutability ---
    features["pure_funcs"] += len(re.findall(r'\bpure\b', content))
    features["view_funcs"] += len(re.findall(r'\bview\b', content))
    features["payable_funcs"] += len(re.findall(r'\bpayable\b', content))

    # --- State variables ---
    features["state_vars"] += len(re.findall(r'\bpublic\s+sv\d+', content))
    features["transient_vars"] += len(re.findall(r'\btransient\b', content))
    features["constant_vars"] += len(re.findall(r'\bconstant\s+public\b', content))
    features["immutable_vars"] += len(re.findall(r'\bimmutable\s+public\b', content))

    # --- Types ---
    features["structs"] += len(re.findall(r'\bstruct\s+S\d+', content))
    features["enums"] += len(re.findall(r'\benum\s+E\d+', content))
    features["arrays_fixed"] += len(re.findall(r'\bpublic\s+sv\d+.*\[\d+\]', content))
    features["arrays_dynamic"] += len(re.findall(r'\bpublic\s+sv\d+.*\[\]', content))
    features["mappings"] += len(re.findall(r'\bmapping\(', content))

    # --- Events & errors ---
    features["events"] += len(re.findall(r'\bevent\s+Ev\d+', content))
    features["indexed_params"] += len(re.findall(r'\buint256\s+indexed\b', content))
    features["errors"] += len(re.findall(r'\berror\s+Err\d+', content))
    features["emit_stmts"] += len(re.findall(r'\bemit\s+Ev\d+', content))
    features["revert_stmts"] += len(re.findall(r'\brevert\s+Err\d+', content))

    # --- Control flow ---
    features["if_stmts"] += len(re.findall(r'\bif\s*\(', content))
    features["for_loops"] += len(re.findall(r'\bfor\s*\(', content))
    features["while_loops"] += len(re.findall(r'\bwhile\s*\(', content))
    features["do_while_loops"] += len(re.findall(r'\bdo\s*\{', content))
    features["unchecked_blocks"] += len(re.findall(r'\bunchecked\s*\{', content))
    features["try_catch"] += len(re.findall(r'\btry\s+this\.', content))
    features["break_stmts"] += len(re.findall(r'\bbreak;', content))
    features["continue_stmts"] += len(re.findall(r'\bcontinue;', content))

    # --- Expressions ---
    features["func_calls"] += len(re.findall(r'\bf\d+_\d+\(', content))
    features["named_args"] += len(re.findall(r'\bf\d+_\d+\(\{', content))
    features["super_calls"] += len(re.findall(r'\bsuper\.', content))
    features["type_conversions"] += len(re.findall(r'\buint\d+\(', content))
    features["ternary_ops"] += content.count(" ? ")
    features["assign_ops"] += len(re.findall(r'[+\-*/%&|^]=[^=]', content))

    # --- Require / assert ---
    features["require_stmts"] += len(re.findall(r'\brequire\(', content))
    features["require_custom_error"] += len(re.findall(r'\brequire\([^)]+,\s*Err\d+', content))
    features["assert_stmts"] += len(re.findall(r'\bassert\(', content))

    # --- Builtins ---
    features["keccak256"] += len(re.findall(r'\bkeccak256\(', content))
    features["abi_encode"] += len(re.findall(r'\babi\.encode\b', content))
    features["abi_encodePacked"] += len(re.findall(r'\babi\.encodePacked\b', content))
    features["abi_encodeWithSelector"] += len(re.findall(r'\babi\.encodeWithSelector\b', content))
    features["abi_encodeWithSignature"] += len(re.findall(r'\babi\.encodeWithSignature\b', content))
    features["ecrecover"] += len(re.findall(r'\becrecover\(', content))
    features["addmod_mulmod"] += len(re.findall(r'\b(?:addmod|mulmod)\(', content))
    features["sha256_ripemd"] += len(re.findall(r'\b(?:sha256|ripemd160)\(', content))
    features["blockhash"] += len(re.findall(r'\bblockhash\(', content))
    features["blobhash"] += len(re.findall(r'\bblobhash\(', content))
    features["msg_sender"] += len(re.findall(r'\bmsg\.sender\b', content))
    features["msg_value"] += len(re.findall(r'\bmsg\.value\b', content))
    features["block_timestamp"] += len(re.findall(r'\bblock\.timestamp\b', content))
    features["selfdestruct"] += len(re.findall(r'\bselfdestruct\(', content))
    features["type_min_max"] += len(re.findall(r'\btype\(\w+\)\.\w+', content))
    features["bytes_concat"] += len(re.findall(r'\bbytes\.concat\(', content))
    features["string_concat"] += len(re.findall(r'\bstring\.concat\(', content))
    features["selector_expr"] += len(re.findall(r'\bthis\.\w+\.selector\b', content))
    features["enum_literals"] += len(re.findall(r'\bE\d+_\d+\.E\d+_\d+_m\d+', content))
    features["delete_stmts"] += len(re.findall(r'\bdelete\s+v\d+', content))

    # --- New features (from this PR) ---
    features["ether_units"] += len(re.findall(r'\d+\s+(?:wei|gwei|ether)\b', content))
    features["array_push"] += len(re.findall(r'\bsv\d+_\d+\.push\(', content))
    features["array_pop"] += len(re.findall(r'\bsv\d+_\d+\.pop\(\)', content))
    features["array_length_expr"] += len(re.findall(r'\bsv\d+_\d+\.length\b', content))
    features["returns_two"] += len(re.findall(r'returns\s*\(uint256,\s*uint256\)', content))
    features["tuple_destruct"] += len(re.findall(r'\(uint256\s+v\d+,\s*uint256\s+v\d+\)\s*=', content))
    features["free_func_calls"] += len(re.findall(r'\bff\d+\(', content))

    # --- Modifiers ---
    features["modifiers"] += len(re.findall(r'\bmodifier\s+mod\d+', content))
    features["virtual_funcs"] += len(re.findall(r'\bvirtual\b', content))
    features["override_funcs"] += len(re.findall(r'\boverride\b', content))

    # --- Library / using-for ---
    features["using_for"] += len(re.findall(r'\busing\s+C\d+\s+for\b', content))
    features["lib_member_calls"] += len(re.findall(r'\.\w+\.\w+\(', content))

    # --- CREATE2 ---
    features["create2"] += len(re.findall(r'\{salt:', content))

    # --- Tuple assign ---
    features["tuple_assign"] += len(re.findall(r'\(v\d+,\s*v\d+\)\s*=\s*\(', content))

    # --- Index assign ---
    features["index_assign"] += len(re.findall(r'\bsv\d+_\d+\[', content))

    # --- Calldataload/size ---
    features["calldataload"] += len(re.findall(r'\b_cdl\d+\(', content))
    features["calldatasize"] += len(re.findall(r'\b_cds\d+\(', content))

    return features


def main():
    parser = argparse.ArgumentParser(description="Check generated Solidity files")
    parser.add_argument("sol_dir", help="Directory containing .sol files")
    parser.add_argument("--solc", default="solc", help="Path to solc binary")
    parser.add_argument("--no-compile", action="store_true", help="Skip compilation, only tally features")
    parser.add_argument("--max-files", type=int, default=0, help="Max files to process (0=all)")
    args = parser.parse_args()

    sol_files = sorted(glob.glob(os.path.join(args.sol_dir, "*.sol")))
    if not sol_files:
        print(f"No .sol files found in {args.sol_dir}")
        sys.exit(1)

    if args.max_files > 0:
        sol_files = sol_files[:args.max_files]

    print(f"Found {len(sol_files)} .sol files in {args.sol_dir}\n")

    # --- Compilation ---
    total_errors = 0
    total_warnings = 0
    error_files = []
    warning_types = Counter()
    error_types = Counter()

    if not args.no_compile:
        print("Compiling...")
        for i, f in enumerate(sol_files):
            if (i + 1) % 500 == 0:
                print(f"  {i + 1}/{len(sol_files)}...")
            errs, warns = compile_file(args.solc, f)
            if errs:
                total_errors += len(errs)
                error_files.append((f, errs))
                for e in errs:
                    # Extract error type (e.g. "TypeError", "DeclarationError")
                    m = re.search(r'(\w+Error):', e)
                    error_types[m.group(1) if m else "Other"] += 1
            if warns:
                total_warnings += len(warns)
                for w in warns:
                    m = re.search(r'(\w+Warning):', w)
                    if not m:
                        m = re.search(r'Warning:\s*(.{0,60})', w)
                    warning_types[m.group(1) if m else "Other"] += 1

        print(f"\n{'='*60}")
        print(f"COMPILATION RESULTS")
        print(f"{'='*60}")
        print(f"Files compiled:  {len(sol_files)}")
        print(f"Files with errors: {len(error_files)}")
        print(f"Total errors:    {total_errors}")
        print(f"Total warnings:  {total_warnings}")

        if error_types:
            print(f"\nError types:")
            for etype, count in error_types.most_common():
                print(f"  {etype}: {count}")

        if warning_types:
            print(f"\nWarning types:")
            for wtype, count in warning_types.most_common():
                print(f"  {wtype}: {count}")

        if error_files:
            print(f"\nFirst 10 files with errors:")
            for f, errs in error_files[:10]:
                print(f"  {os.path.basename(f)}:")
                for e in errs[:3]:
                    print(f"    {e[:120]}")
        print()

    # --- Feature tally ---
    print(f"{'='*60}")
    print(f"FEATURE TALLY")
    print(f"{'='*60}")

    total_features = Counter()
    files_with_feature = Counter()

    for f in sol_files:
        try:
            with open(f, "r") as fh:
                content = fh.read()
        except Exception:
            continue
        features = tally_features(content)
        total_features += features
        for feat, count in features.items():
            if count > 0:
                files_with_feature[feat] += 1

    # Group features for display
    groups = {
        "Contract Structure": [
            "contracts", "libraries", "inheritance", "constructors",
            "receive_funcs", "fallback_funcs", "modifiers",
            "virtual_funcs", "override_funcs", "using_for", "create2",
        ],
        "Functions": [
            "functions", "free_functions", "pure_funcs", "view_funcs",
            "payable_funcs", "func_calls", "named_args", "super_calls",
            "free_func_calls", "lib_member_calls",
        ],
        "State Variables": [
            "state_vars", "transient_vars", "constant_vars", "immutable_vars",
        ],
        "Types": [
            "structs", "enums", "arrays_fixed", "arrays_dynamic", "mappings",
        ],
        "Events & Errors": [
            "events", "indexed_params", "errors", "emit_stmts", "revert_stmts",
        ],
        "Control Flow": [
            "if_stmts", "for_loops", "while_loops", "do_while_loops",
            "unchecked_blocks", "try_catch", "break_stmts", "continue_stmts",
        ],
        "Expressions": [
            "type_conversions", "ternary_ops", "assign_ops",
            "enum_literals", "selector_expr", "tuple_assign", "index_assign",
        ],
        "Error Handling": [
            "require_stmts", "require_custom_error", "assert_stmts",
            "delete_stmts", "selfdestruct",
        ],
        "Builtins": [
            "keccak256", "abi_encode", "abi_encodePacked",
            "abi_encodeWithSelector", "abi_encodeWithSignature",
            "ecrecover", "addmod_mulmod", "sha256_ripemd",
            "blockhash", "blobhash", "msg_sender", "msg_value",
            "block_timestamp", "type_min_max", "bytes_concat", "string_concat",
            "calldataload", "calldatasize",
        ],
        "New Features (this PR)": [
            "ether_units", "indexed_params", "array_push", "array_pop",
            "array_length_expr", "returns_two", "tuple_destruct",
            "require_custom_error", "free_functions", "free_func_calls",
        ],
    }

    for group_name, feat_list in groups.items():
        print(f"\n  {group_name}:")
        for feat in feat_list:
            total = total_features.get(feat, 0)
            nfiles = files_with_feature.get(feat, 0)
            if total > 0:
                print(f"    {feat:30s}  total={total:6d}  files={nfiles:5d}/{len(sol_files)}")
            else:
                print(f"    {feat:30s}  (none)")

    # Summary of zero-count features
    zero_features = [f for f in sorted(total_features.keys()) if total_features[f] == 0]
    if zero_features:
        print(f"\n  Features with zero occurrences: {', '.join(zero_features)}")

    print()


if __name__ == "__main__":
    main()
