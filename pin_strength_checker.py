"""
Bank Card PIN Strength Checker
--------------------------------
Checks a 4-digit bank card PIN against common weaknesses:

  1. Length       - must be exactly 4 digits, numeric only
  2. Sequential    - flags ascending/descending runs (e.g. 1234, 4321, 0123)
  3. Repeated      - flags PINs made of one or two repeating digits (e.g. 1111, 1212)
  4. Common/weak   - flags PINs found in published lists of most-common PINs

Usage:
    python pin_strength_checker.py            # interactive prompt
    python pin_strength_checker.py 1234        # check a single PIN via argument
    python pin_strength_checker.py --batch pins.txt   # check many PINs from a file (one per line)

Author: Zizipho Ntlantsana
"""

import sys
import argparse  # lets us parse command-line arguments like `--batch pins.txt`


# A curated subset of the most common 4-digit PINs, based on widely published
# analyses of leaked PIN datasets (e.g. Data Genetics' 2012 PIN frequency study).
# These are among the first PINs an attacker would try — this is essentially
# a tiny "dictionary attack" wordlist, the same concept used in real password
# and PIN cracking tools.
COMMON_WEAK_PINS = {
    "0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999",
    "1234", "4321", "1212", "1004", "2000", "2580", "0852", "6969", "1122", "1313",
    "1004", "0007", "1010", "2001", "1990", "1991", "1992", "1993", "1994", "1995",
    "9999", "1000", "1001", "2020", "2021", "2022", "2023", "2024", "2025", "2026",
}


def is_correct_length(pin: str) -> bool:
    """A valid bank card PIN is exactly 4 numeric digits."""
    # .isdigit() confirms every character is 0-9 (rejects letters, symbols, spaces)
    # len() confirms it's exactly 4 characters, not 3 or 5
    return pin.isdigit() and len(pin) == 4


def is_sequential(pin: str) -> bool:
    """True if digits form an ascending or descending run, e.g. 1234, 4321, 0123, 9876."""
    # Convert the string "1234" into a list of actual integers [1, 2, 3, 4]
    # so we can do maths on each digit (comparing string characters won't work the same way).
    digits = [int(d) for d in pin]

    # Check every consecutive pair: does each digit equal the previous one + 1?
    # all() returns True only if EVERY pair in the sequence satisfies the condition.
    ascending = all(digits[i] + 1 == digits[i + 1] for i in range(len(digits) - 1))

    # Same idea, but checking for a descending run (each digit is previous - 1).
    descending = all(digits[i] - 1 == digits[i + 1] for i in range(len(digits) - 1))

    # It's sequential if it matches either pattern.
    return ascending or descending


def is_repeated(pin: str) -> bool:
    """True if the PIN uses only one or two distinct digits (e.g. 1111, 1212, 1122)."""
    # set(pin) collects only the UNIQUE characters. "1212" becomes {"1", "2"} -> length 2.
    # "1234" becomes {"1","2","3","4"} -> length 4.
    # A PIN with only 1 or 2 distinct digits has very little real variety, so it's weak.
    return len(set(pin)) <= 2


def is_common(pin: str) -> bool:
    """True if the PIN appears in the known list of most-common/weak PINs."""
    # Checking membership in a set is fast (O(1) average) and simple to read.
    return pin in COMMON_WEAK_PINS


def check_pin(pin: str) -> dict:
    """
    Run all checks against a PIN and return a result dict:
        {
            "pin": str,
            "valid_format": bool,
            "issues": list[str],
            "strength": "Invalid" | "Weak" | "Moderate" | "Strong"
        }
    """
    # Start with a default "nothing checked yet" result.
    result = {"pin": pin, "valid_format": False, "issues": [], "strength": "Invalid"}

    # If the format itself is wrong, there's no point running the other checks —
    # exit early and report it as Invalid.
    if not is_correct_length(pin):
        result["issues"].append("PIN must be exactly 4 numeric digits.")
        return result

    # Format is fine, so mark it valid before running the pattern checks.
    result["valid_format"] = True

    # Run each pattern check and record a human-readable reason if it fails.
    # Note: a PIN can trigger MORE THAN ONE of these at once (e.g. "1111" is both
    # repeated AND common) — we collect all of them, not just the first match.
    if is_sequential(pin):
        result["issues"].append("Sequential digits (e.g. 1234, 4321) are easy to guess.")
    if is_repeated(pin):
        result["issues"].append("Repeated/low-variety digits (e.g. 1111, 1212) are easy to guess.")
    if is_common(pin):
        result["issues"].append("This PIN is on a list of the most commonly used PINs.")

    # Turn the number of issues found into a simple strength rating.
    issue_count = len(result["issues"])
    if issue_count == 0:
        result["strength"] = "Strong"
    elif issue_count == 1:
        result["strength"] = "Moderate"
    else:
        result["strength"] = "Weak"

    return result


def print_result(result: dict) -> None:
    """Pretty-print a single check_pin() result to the terminal."""
    print(f"\nPIN: {result['pin']}")
    print(f"Strength: {result['strength']}")
    if result["issues"]:
        print("Issues found:")
        for issue in result["issues"]:
            print(f"  - {issue}")
    elif result["valid_format"]:
        # Only reachable if valid_format is True AND there are no issues -> Strong PIN.
        print("No issues found — this PIN avoids the common weaknesses checked here.")


def run_batch(filepath: str) -> None:
    """Read a text file of PINs (one per line) and check each one."""
    try:
        with open(filepath, "r") as f:
            # strip() removes trailing newlines/whitespace from each line;
            # the `if line.strip()` skips any blank lines in the file.
            pins = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: file '{filepath}' not found.")
        sys.exit(1)  # exit the program with a non-zero code to signal failure

    print(f"Checking {len(pins)} PIN(s) from '{filepath}'...")
    for pin in pins:
        print_result(check_pin(pin))


def main():
    """Entry point: decide whether to run in batch, single-argument, or interactive mode."""
    parser = argparse.ArgumentParser(
        description="Check the strength of a 4-digit bank card PIN."
    )
    # nargs="?" means this argument is OPTIONAL — the script still runs without it.
    parser.add_argument("pin", nargs="?", help="A 4-digit PIN to check (optional).")
    parser.add_argument(
        "--batch", metavar="FILE", help="Path to a text file of PINs, one per line."
    )
    args = parser.parse_args()

    # Priority: batch file > single PIN argument > interactive prompt.
    if args.batch:
        run_batch(args.batch)
    elif args.pin:
        print_result(check_pin(args.pin))
    else:
        pin = input("Enter a 4-digit PIN to check: ").strip()
        print_result(check_pin(pin))


# This guard means main() only runs when the file is executed directly
# (e.g. `python pin_strength_checker.py`), NOT when it's imported by
# test_pin_strength_checker.py — important, since our tests import functions
# from this file and we don't want that import to also trigger the CLI.
if __name__ == "__main__":
    main()