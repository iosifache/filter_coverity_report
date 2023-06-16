#!/usr/bin/env python3

import re
import sys
import typing

# PII: Program Identifiable Information ;)


class Sanitizer:
    @staticmethod
    def _remove_pii_data(data: str) -> str:
        pii_map = {
            r"held [0-9]+ out of [0-9]+ times": "held <pii> out of <pii> times",
            r"checked [0-9]+ out of [0-9]+ times": "checked <pii> out of <pii> times",
            r"uses [0-9]+ bytes of stack space, which exceeds the maximum single use of [0-9]+ bytes": "uses <pii> bytes of stack space, which exceeds the maximum single use of <pii> bytes",
            r"\(count: [0-9]+ / [0-9]+\)": "(count: <pii> / <pii>)",
            r"\".*?\"": "<pii>",
        }

        for key, value in pii_map.items():
            data = re.sub(key, value, data)

        return data

    @staticmethod
    def _standardize_errors(error: str) -> str:
        content_map = {
            ", taking false branch.": "Condition <pii>, taking false branch.",
            ", taking true branch.": "Condition <pii>, taking true branch.",
            "check_return": "check_return: Calling <pii> without checking return value. This library function may fail and return an error code.",
            "example_access": "example_access: <pii> is written to with lock <pii> held.",
            "example_assign": "example_assign: Assigning: <pii> = return value from <pii>.",
            "example_checked:": "example_checked: <pii> has its value checked in <pii>.",
            "example_lock_order": "example_lock_order: Calling <pii> acquires lock <pii> while holding <pii>.",
            "fs_check_call": "Calling function <pii> to perform check on <pii>",
            "getlock": "getlock: Acquiring lock named <pii>",
            "leaked_handle": "leaked_handle: Ignoring handle opened by <pii>",
            "lock_acquire": "lock_acquire: Calling <pii> acquires lock <pii>.",
            "lock_order": "lock_order: Calling <pii> acquires lock <pii> while holding lock <pii> (count: <pii> / <pii>).",
            "missing_lock": "missing_lock: Accessing <pii> without holding lock <pii>. Elsewhere, <pii> is written to with <pii> held <pii> out of <pii> times.",
            "open_fn": "open_fn: Returning handle opened by <pii>",
            "returned_null": "returned_null: <pii> returns <pii> (checked <pii> out of <pii> times).",
            "stack_use_local_overflow": "Local variable <pii> uses <pii> bytes of stack space, which exceeds the maximum single use of <pii> bytes.",
            "toctou": "toctou: Calling function <pii> that uses <pii> after a check function. This can cause a time-of-check, time-of-use race condition.",
            "var_assigned": "var_assigned: Assigning: <pii> = <pii> return value from <pii>.",
        }
        replace_map = {
            r"([0-9]+\.)+ ": "",
            r"Example [0-9]+[ \(cont.\)]*: ": ""
        }

        for key, value in content_map.items():       
            if key in error:
                return value

        for key, value in replace_map.items():
            error = re.sub(key, value, error)

        return error
    
    @staticmethod
    def sanitize_error(error: str) -> str:
        error = Sanitizer._remove_pii_data(error)
        error = Sanitizer._standardize_errors(error)

        return error

    @staticmethod
    def sanitize_scope(scope: str) -> str:
        scope = Sanitizer._remove_pii_data(scope)

        return scope

class ErrorsIndex:
    _index: dict

    def __init__(self) -> None:
        self._index = {}

    def add_error(self, error: str, scope: str):
        error = Sanitizer.sanitize_error(error)
        scope = Sanitizer.sanitize_scope(scope)

        if error not in self._index:
            self._index[error] = [scope]
        else:
            self._index[error].append(scope)

    def get_index(self) -> dict:
        return self._index

    def count_errors(self) -> int:
        return len(self._index.keys())

    def get_unique_sorted_errors(self) -> typing.List[str]:
        errors = list(self._index.keys())
        errors.sort()

        return errors


if len(sys.argv) != 3:
    exit(0)

report_filename = sys.argv[1]
max_lines_count = int(sys.argv[2])

index = ErrorsIndex()
with open(report_filename, "r") as report:
    content = report.read()

    lines_count = 0
    was_previously_scope = False
    scope = None
    error = None
    for line in content.split("\n"):
        line = line.strip()

        if re.match(r".*?\:[0-9]+:[0-9]+:", line):
            scope = line
            was_previously_scope = True
        else:
            if was_previously_scope:
                error = line

            if scope != None:                
                index.add_error(error, scope)

            was_previously_scope = False

        lines_count += 1
        if (lines_count > max_lines_count):
            break

errors_count = index.count_errors()
print(f"Found a total of {errors_count} different errors:")
for error in index.get_unique_sorted_errors():
    print(f"- {error}")

