# `filter_coverity_report`

## Description

`filter_coverity_report` is a Python script for getting insight from a Coverity report.

At the moment, it only generates aggregations of findings: vulnerability classes (e.g. "*Large stack use*") and their indicators (e.g. "*stack_use_local_overflow: Local variable "supply" uses 27200 bytes of stack space, which exceeds the maximum single use of 10000 bytes.*"):

```
source.c:1383:18:
  Type: Large stack use (STACK_USE)

source.c:1383:18:
  stack_use_local_overflow: Local variable "supply" uses 27200 bytes of stack space, which exceeds the maximum single use of 10000 bytes.
```

All entries are standardized, with all program-specific information (abbreviated with PII) being replaced with `<pii>`.

## Setup

Just run `pip install -r requirements.txt`.

## Usage

`python3 filter_coverity_report.py --report <report_path> [--limit <max_lines_processed>]`

### Example of Run

```bash
$ python3 filter_coverity_report.py --report coverity.txt --limit 100
Found a total of 2 different vulnerability classes:
- Unchecked return value (CHECKED_RETURN)
- Unchecked return value from library (CHECKED_RETURN)

Found a total of 5 different descriptors:
- Condition <pii>, taking false branch.
- Condition <pii>, taking true branch.
- check_return: Calling <pii> without checking return value. This library function may fail and return an error code.
- path: Continuing loop.
- path: Jumping back to the beginning of the loop.
```
