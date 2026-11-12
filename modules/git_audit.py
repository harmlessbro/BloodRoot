import os
import subprocess


class GitAuditor:

    def __init__(self, path):

        self.path = os.path.abspath(
            os.path.expanduser(path)
        )

    def git(self, repo, *args):

        try:

            result = subprocess.run(
                ["git", *args],
                cwd=repo,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return ""

            return result.stdout.strip()

        except Exception:

            return ""

    def find_repositories(self):

        repositories = []

        if not os.path.exists(self.path):

            return repositories

        if os.path.isdir(
            os.path.join(
                self.path,
                ".git"
            )
        ):

            return [self.path]

        for root, dirs, files in os.walk(
            self.path
        ):

            if ".git" in dirs:

                repositories.append(root)

                dirs.remove(".git")

        return repositories

    def audit_repo(self, repo):

        result = {
            "path": repo,
            "current_identity": {},
            "historical_identities": [],
            "branches": [],
            "remotes": [],
            "first_commit": None,
            "last_commit": None
        }

        # Current config

        name = self.git(
            repo,
            "config",
            "user.name"
        )

        email = self.git(
            repo,
            "config",
            "user.email"
        )

        result["current_identity"] = {
            "name": name,
            "email": email
        }

        # Remotes

        remotes = self.git(
            repo,
            "remote",
            "-v"
        )

        if remotes:

            result["remotes"] = (
                remotes.splitlines()
            )

        # Branches

        branches = self.git(
            repo,
            "branch",
            "--all"
        )

        if branches:

            result["branches"] = (
                branches.splitlines()
            )

        # Historical identities

        log = self.git(
            repo,
            "log",
            "--all",
            "--format=%an <%ae>|%cn <%ce>|%ad",
            "--date=iso"
        )

        identities = set()

        dates = []

        for line in log.splitlines():

            parts = line.split("|")

            if len(parts) != 3:
                continue

            author = parts[0]
            committer = parts[1]
            date = parts[2]

            identities.add(author)
            identities.add(committer)

            dates.append(date)

        result["historical_identities"] = sorted(
            identities
        )

        if dates:

            result["first_commit"] = min(
                dates
            )

            result["last_commit"] = max(
                dates
            )

        return result

    def run(self):

        repositories = self.find_repositories()

        results = []

        findings = []

        all_identities = set()

        for repo in repositories:

            print(
                f"[*] Auditing: {repo}"
            )

            result = self.audit_repo(
                repo
            )

            results.append(result)

            for identity in result[
                "historical_identities"
            ]:

                all_identities.add(
                    identity
                )

        # Find historical emails

        historical_emails = set()

        for identity in all_identities:

            if "<" in identity and ">" in identity:

                email = identity.split(
                    "<", 1
                )[1].split(
                    ">",
                    1
                )[0]

                historical_emails.add(
                    email
                )

        for email in historical_emails:

            if "noreply.github.com" not in email:

                findings.append(
                    f"Historical email discovered: {email}"
                )

        return {
            "path": self.path,
            "repositories": results,
            "historical_emails": sorted(
                historical_emails
            ),
            "findings": findings
        }

    def display(self, data):

        print("\n" + "=" * 65)
        print("                     LOCAL GIT AUDIT")
        print("=" * 65)

        print(
            f"\nRepositories: "
            f"{len(data['repositories'])}"
        )

        for repo in data["repositories"]:

            print(
                "\n--------------------------------"
            )

            print(
                f"Repository: {repo['path']}"
            )

            current = repo[
                "current_identity"
            ]

            print(
                f"Current name : "
                f"{current.get('name')}"
            )

            print(
                f"Current email: "
                f"{current.get('email')}"
            )

            print(
                "\nHistorical identities:"
            )

            for identity in repo[
                "historical_identities"
            ]:

                print(
                    f"  {identity}"
                )

            print(
                f"\nFirst commit: "
                f"{repo.get('first_commit')}"
            )

            print(
                f"Last commit : "
                f"{repo.get('last_commit')}"
            )

        print("\n--- HISTORICAL EMAILS ---")

        for email in data[
            "historical_emails"
        ]:

            marker = (
                "NOREPLY"
                if "noreply.github.com" in email
                else "POTENTIAL EXPOSURE"
            )

            print(
                f"[{marker}] {email}"
            )

        print("\n--- FINDINGS ---")

        for finding in data["findings"]:

            print(
                f"[!] {finding}"
            )