#!/usr/bin/env python3

import re
import sys
import typing

import click


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

        if not data:
            return data

        for key, value in pii_map.items():
            data, sub_count = re.subn(key, value, data)
            if sub_count != 0:
                continue

        return data

    @staticmethod
    def _standardize_findings(finding: str) -> str:
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
            r"Example [0-9]+[ \(cont.\)]*: ": "",
            "Type: ": "",
        }

        for key, value in content_map.items():
            if key in finding:
                return value

        for key, value in replace_map.items():
            finding = re.sub(key, value, finding)

        return finding

    @staticmethod
    def sanitize_finding(finding: str) -> str:
        finding = Sanitizer._remove_pii_data(finding)
        finding = Sanitizer._standardize_findings(finding)

        return finding

    @staticmethod
    def sanitize_scope(scope: str) -> str:
        scope = Sanitizer._remove_pii_data(scope)

        return scope


class FindingsIndex:
    _index: dict
    _object_names: str

    def __init__(self, object_names: str = None) -> None:
        self._index = {}
        self._object_names = object_names if object_names else "findings"

    def add_finding(self, finding: str, scope: str) -> None:
        finding = Sanitizer.sanitize_finding(finding)
        scope = Sanitizer.sanitize_scope(scope)

        if finding not in self._index:
            self._index[finding] = [scope]
        else:
            self._index[finding].append(scope)

    def get_index(self) -> dict:
        return self._index

    def count_findings(self) -> int:
        return len(self._index.keys())

    def get_unique_sorted_findings(self) -> typing.List[str]:
        findings = list(self._index.keys())
        findings.sort()

        return findings

    def print_content(self) -> None:
        count = self.count_findings()
        print(f"Found a total of {count} different {self._object_names}:")
        for finding in self.get_unique_sorted_findings():
            print(f"- {finding}")


@click.command()
@click.option(
    "--report",
    type=str,
    required=True,
    help="Name of the report.",
)
@click.option(
    "--limit",
    type=int,
    help="Maximum number of report's lines to process",
)
def parse(report: str, limit: int = None) -> None:
    if not limit:
        limit = sys.maxsize

    vuln_index = FindingsIndex(object_names="vulnerability classes")
    descriptors_index = FindingsIndex(object_names="descriptors")
    with open(report, "r") as report_fd:
        content = report_fd.read()

        lines_count = 0
        scope = None
        description = None
        for line in content.split("\n"):
            line = line.strip()
            if not line:
                continue

            if re.match(r".*?\:[0-9]+:[0-9]+:", line):
                scope = line
            elif scope != None:
                description = line

                if "Type: " in line:
                    vuln_index.add_finding(description, scope)
                else:
                    descriptors_index.add_finding(description, scope)

                scope = False

            lines_count += 1
            if lines_count > limit:
                break

    vuln_index.print_content()
    print("")
    descriptors_index.print_content()


if __name__ == "__main__":
    parse()
