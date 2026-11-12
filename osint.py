#!/usr/bin/env python3

import argparse
import json
import os
import sys
from datetime import datetime

from modules.github import GitHubAuditor
from modules.github_deep import GitHubDeepAuditor
from modules.username import UsernameScanner
from modules.email import EmailAuditor
from modules.git_audit import GitAuditor


BANNER = r"""
 __  (\_ 
(_ \ ( '> 
  ) \/_)=
  (_(_ )_
    ____  __    ____  ____  ____  ____  ____  ____  ______                    
   / __ )/ /   / __ \/ __ \/ __ \/ __ \/ __ \/ __ \/_  __/  
  / __  / /   / / / / / / / / / / /_/ / / / / / / / / /   
 / /_/ / /___/ /_/ / /_/ / /_/ / _, _/ /_/ / /_/ / / /    
/_____/_____/\____/\____/_____/_/ |_|\____/\____/ /_/       
                                                          

                [ DIGITAL PLAGUE OF INTELLIGENCE ]
"""


def get_github_token(cli_token=None):
    """
    Get GitHub token.

    Priority:
    1. --token argument
    2. GITHUB_TOKEN environment variable
    """

    return cli_token or os.getenv("GITHUB_TOKEN")


def save_report(data, output):
    """Save results to a JSON file."""

    directory = os.path.dirname(output)

    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(
        output,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=2,
            ensure_ascii=False
        )

    print(
        f"\n[+] Report saved: {output}"
    )


def print_summary(results):
    """Display findings from all completed modules."""

    print("\n" + "=" * 65)
    print("                         SUMMARY")
    print("=" * 65)

    for name, result in results.items():

        if not isinstance(result, dict):
            continue

        findings = result.get(
            "findings",
            []
        )

        if not findings:
            continue

        print(f"\n[{name}]")

        for finding in findings:
            print(
                f"  {finding}"
            )


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Passive self-OSINT and "
            "OPSEC auditing toolkit"
        )
    )

    sub = parser.add_subparsers(
        dest="command"
    )

    # ==================================================
    # GITHUB
    # ==================================================

    github = sub.add_parser(
        "github",
        help="GitHub account audit"
    )

    github.add_argument(
        "username",
        help="GitHub username"
    )

    github.add_argument(
        "--token",
        help="Optional GitHub token"
    )

    github.add_argument(
        "--pages",
        type=int,
        default=5,
        help="Maximum pagination depth"
    )

    # ==================================================
    # DEEP GITHUB
    # ==================================================

    deep_github = sub.add_parser(
        "github-deep",
        help="Deep GitHub account OSINT audit"
    )

    deep_github.add_argument(
        "username",
        help="GitHub username"
    )

    deep_github.add_argument(
        "--token",
        help="Optional GitHub token"
    )

    # ==================================================
    # USERNAME
    # ==================================================

    username = sub.add_parser(
        "username",
        help="Check username presence on public services"
    )

    username.add_argument(
        "name",
        help="Username to check"
    )

    # ==================================================
    # EMAIL
    # ==================================================

    email = sub.add_parser(
        "email",
        help="Audit an email address"
    )

    email.add_argument(
        "address",
        help="Email address"
    )

    # ==================================================
    # GIT
    # ==================================================

    git = sub.add_parser(
        "git",
        help="Audit local Git repositories"
    )

    git.add_argument(
        "path",
        help="Directory containing repositories"
    )

    # ==================================================
    # FULL
    # ==================================================

    full = sub.add_parser(
        "full",
        help="Run complete self-OSINT audit"
    )

    full.add_argument(
        "--username",
        help="GitHub username"
    )

    full.add_argument(
        "--email",
        help="Email address"
    )

    full.add_argument(
        "--repo",
        help="Local Git repository or parent directory"
    )

    full.add_argument(
        "--token",
        help="Optional GitHub token"
    )

    full.add_argument(
        "--output",
        default="reports/osint-report.json",
        help="Output JSON report"
    )

    # ==================================================
    # PARSE
    # ==================================================

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    print(BANNER)

    # Resolve GitHub token once.
    github_token = get_github_token(
        getattr(args, "token", None)
    )

    if github_token:
        print("[+] GitHub API authentication enabled")
    else:
        print("[!] GitHub API running without authentication")

    results = {
        "metadata": {
            "tool": "Self-OSINT",
            "started": datetime.now().isoformat()
        }
    }

    # ==================================================
    # GITHUB
    # ==================================================

    if args.command == "github":

        print(
            "\n[*] Running GitHub audit..."
        )

        auditor = GitHubAuditor(
            args.username,
            token=github_token,
            max_pages=args.pages
        )

        result = auditor.run()

        results["github"] = result

        auditor.display(result)

    # ==================================================
    # DEEP GITHUB
    # ==================================================

    elif args.command == "github-deep":

        print(
            "\n[*] Running deep GitHub audit..."
        )

        auditor = GitHubDeepAuditor(
            args.username,
            token=github_token
        )

        result = auditor.run()

        results["github_deep"] = result

        auditor.display(result)

        # Deep GitHub results are displayed
        # directly in the terminal.
        # No JSON report is created here.

    # ==================================================
    # USERNAME
    # ==================================================

    elif args.command == "username":

        print(
            "\n[*] Running username audit..."
        )

        scanner = UsernameScanner(
            args.name
        )

        result = scanner.run()

        results["username"] = result

        scanner.display(result)

    # ==================================================
    # EMAIL
    # ==================================================

    elif args.command == "email":

        print(
            "\n[*] Running email audit..."
        )

        auditor = EmailAuditor(
            args.address
        )

        result = auditor.run()

        results["email"] = result

        auditor.display(result)

    # ==================================================
    # GIT
    # ==================================================

    elif args.command == "git":

        print(
            "\n[*] Running local Git audit..."
        )

        auditor = GitAuditor(
            args.path
        )

        result = auditor.run()

        results["git"] = result

        auditor.display(result)

    # ==================================================
    # FULL
    # ==================================================

    elif args.command == "full":

        if not any([
            args.username,
            args.email,
            args.repo
        ]):

            print(
                "[!] Provide at least one target."
            )

            sys.exit(1)

        # ----------------------------------------------
        # GITHUB
        # ----------------------------------------------

        if args.username:

            print(
                "\n[*] Running GitHub audit..."
            )

            auditor = GitHubAuditor(
                args.username,
                token=github_token
            )

            result = auditor.run()

            results["github"] = result

            auditor.display(result)

        # ----------------------------------------------
        # EMAIL
        # ----------------------------------------------

        if args.email:

            print(
                "\n[*] Running email audit..."
            )

            auditor = EmailAuditor(
                args.email
            )

            result = auditor.run()

            results["email"] = result

            auditor.display(result)

        # ----------------------------------------------
        # LOCAL GIT
        # ----------------------------------------------

        if args.repo:

            print(
                "\n[*] Running local Git audit..."
            )

            auditor = GitAuditor(
                args.repo
            )

            result = auditor.run()

            results["git"] = result

            auditor.display(result)

        # ----------------------------------------------
        # USERNAME
        # ----------------------------------------------

        if args.username:

            print(
                "\n[*] Running username audit..."
            )

            scanner = UsernameScanner(
                args.username
            )

            result = scanner.run()

            results["username"] = result

            scanner.display(result)

        # ----------------------------------------------
        # SUMMARY
        # ----------------------------------------------

        print_summary(results)

        results["metadata"]["finished"] = (
            datetime.now().isoformat()
        )

        save_report(
            results,
            args.output
        )


if __name__ == "__main__":
    main()