import re
import time
import requests
from urllib.parse import urlparse


class GitHubAuditor:

    API = "https://api.github.com"

    def __init__(self, username, token=None, max_pages=5):
        self.username = username
        self.max_pages = max_pages

        self.session = requests.Session()

        self.session.headers.update({
            "Accept": "application/vnd.github+json",
            "User-Agent": "Self-OSINT-Auditor",
            "X-GitHub-Api-Version": "2022-11-28"
        })

        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

    def get(self, endpoint, params=None):

        url = self.API + endpoint

        try:
            response = self.session.get(
                url,
                params=params,
                timeout=20
            )

            if response.status_code == 404:
                return None

            if response.status_code == 403:
                print("[!] GitHub rate limit reached.")
                return None

            response.raise_for_status()

            time.sleep(0.15)

            return response.json()

        except requests.RequestException as e:
            print(f"[!] GitHub request failed: {e}")
            return None

    def paginate(self, endpoint, params=None):

        params = params or {}

        output = []

        for page in range(1, self.max_pages + 1):

            p = params.copy()
            p["page"] = page
            p["per_page"] = 100

            data = self.get(endpoint, p)

            if not data:
                break

            if not isinstance(data, list):
                break

            output.extend(data)

            if len(data) < 100:
                break

        return output

    def extract_urls(self, text):

        if not text:
            return []

        return sorted(set(
            re.findall(
                r'https?://[^\s<>"\')]+',
                text
            )
        ))

    def audit_profile(self):

        return self.get(
            f"/users/{self.username}"
        )

    def audit_repositories(self):

        return self.paginate(
            f"/users/{self.username}/repos",
            {
                "type": "all",
                "sort": "updated"
            }
        )

    def audit_orgs(self):

        return self.paginate(
            f"/users/{self.username}/orgs"
        )

    def audit_followers(self):

        return self.paginate(
            f"/users/{self.username}/followers"
        )

    def audit_following(self):

        return self.paginate(
            f"/users/{self.username}/following"
        )

    def audit_gists(self):

        return self.paginate(
            f"/users/{self.username}/gists"
        )

    def audit_events(self):

        return self.paginate(
            f"/users/{self.username}/events/public"
        )

    def audit_commits(self, repositories):

        commits = []

        for repo in repositories:

            name = repo.get("name")

            if not name:
                continue

            print(f"    [commit] {name}")

            data = self.paginate(
                f"/repos/{self.username}/{name}/commits",
                {
                    "author": self.username
                }
            )

            for commit in data:

                commit_info = commit.get(
                    "commit",
                    {}
                )

                author = commit_info.get(
                    "author",
                    {}
                )

                committer = commit_info.get(
                    "committer",
                    {}
                )

                commits.append({
                    "repository": name,
                    "sha": commit.get("sha"),
                    "message": commit_info.get("message"),
                    "author_name": author.get("name"),
                    "author_email": author.get("email"),
                    "author_date": author.get("date"),
                    "committer_name": committer.get("name"),
                    "committer_email": committer.get("email"),
                    "url": commit.get("html_url")
                })

        return commits

    def audit_readmes(self, repositories):

        results = []

        for repo in repositories:

            name = repo.get("name")

            data = self.get(
                f"/repos/{self.username}/{name}/readme"
            )

            if not data:
                continue

            import base64

            try:
                content = base64.b64decode(
                    data.get("content", "")
                ).decode(
                    "utf-8",
                    errors="ignore"
                )

                results.append({
                    "repository": name,
                    "urls": self.extract_urls(content)
                })

            except Exception:
                continue

        return results

    def run(self):

        findings = []

        profile = self.audit_profile()

        if not profile:
            return {
                "error": "GitHub account not found",
                "findings": []
            }

        repositories = self.audit_repositories()

        orgs = self.audit_orgs()

        followers = self.audit_followers()

        following = self.audit_following()

        gists = self.audit_gists()

        events = self.audit_events()

        print("\n[*] Auditing historical commits...")

        commits = self.audit_commits(
            repositories
        )

        print("\n[*] Extracting README links...")

        readmes = self.audit_readmes(
            repositories
        )

        # ---------------- EMAILS ----------------

        emails = set()

        for commit in commits:

            email = commit.get(
                "author_email"
            )

            if email:
                emails.add(email)

            email = commit.get(
                "committer_email"
            )

            if email:
                emails.add(email)

        # ---------------- NAMES ----------------

        names = set()

        for commit in commits:

            if commit.get("author_name"):
                names.add(
                    commit["author_name"]
                )

            if commit.get("committer_name"):
                names.add(
                    commit["committer_name"]
                )

        # ---------------- DOMAINS ----------------

        domains = set()

        for readme in readmes:

            for url in readme["urls"]:

                try:
                    host = urlparse(
                        url
                    ).hostname

                    if host:
                        domains.add(host)

                except Exception:
                    pass

        # ---------------- FINDINGS ----------------

        if profile.get("email"):
            findings.append(
                "Public profile email exposed"
            )

        if profile.get("location"):
            findings.append(
                "Location is present on public profile"
            )

        if profile.get("company"):
            findings.append(
                "Company/organization information exposed"
            )

        if profile.get("blog"):
            findings.append(
                "External website linked from profile"
            )

        real_emails = [
            x for x in emails
            if "noreply.github.com" not in x
        ]

        if real_emails:
            findings.append(
                f"{len(real_emails)} non-GitHub commit email(s) discovered"
            )

        if domains:
            findings.append(
                f"{len(domains)} external domain(s) found in READMEs"
            )

        return {
            "profile": profile,

            "repositories": [
                {
                    "name": r.get("name"),
                    "url": r.get("html_url"),
                    "description": r.get("description"),
                    "language": r.get("language"),
                    "topics": r.get("topics", []),
                    "stars": r.get("stargazers_count"),
                    "forks": r.get("forks_count"),
                    "created": r.get("created_at"),
                    "updated": r.get("updated_at"),
                    "homepage": r.get("homepage"),
                    "license": (
                        r.get("license") or {}
                    ).get("spdx_id"),
                    "default_branch": r.get(
                        "default_branch"
                    )
                }
                for r in repositories
            ],

            "organizations": [
                {
                    "login": x.get("login"),
                    "url": x.get("html_url")
                }
                for x in orgs
            ],

            "followers": [
                x.get("login")
                for x in followers
            ],

            "following": [
                x.get("login")
                for x in following
            ],

            "gists": [
                {
                    "id": x.get("id"),
                    "description": x.get("description"),
                    "url": x.get("html_url"),
                    "created": x.get("created_at"),
                    "updated": x.get("updated_at")
                }
                for x in gists
            ],

            "public_events": [
                {
                    "type": x.get("type"),
                    "repo": x.get(
                        "repo",
                        {}
                    ).get("name"),
                    "created": x.get("created_at")
                }
                for x in events
            ],

            "commit_emails": sorted(emails),

            "commit_names": sorted(names),

            "commits": commits,

            "readme_links": readmes,

            "external_domains": sorted(domains),

            "findings": findings
        }

    def display(self, data):

        print("\n" + "=" * 65)
        print("                       GITHUB AUDIT")
        print("=" * 65)

        profile = data.get("profile", {})

        print(
            f"\nUsername : {profile.get('login')}"
        )

        print(
            f"Name     : {profile.get('name')}"
        )

        print(
            f"Bio      : {profile.get('bio')}"
        )

        print(
            f"Location : {profile.get('location')}"
        )

        print(
            f"Company  : {profile.get('company')}"
        )

        print(
            f"Website  : {profile.get('blog')}"
        )

        print(
            f"Repos    : {profile.get('public_repos')}"
        )

        print(
            f"Followers: {profile.get('followers')}"
        )

        print(
            f"Following: {profile.get('following')}"
        )

        print("\n--- COMMIT EMAILS ---")

        for email in data.get(
            "commit_emails",
            []
        ):

            marker = (
                "SAFE / NOREPLY"
                if "noreply.github.com" in email
                else "EXPOSED"
            )

            print(
                f"[{marker}] {email}"
            )

        print("\n--- COMMIT NAMES ---")

        for name in data.get(
            "commit_names",
            []
        ):

            print(
                f"  {name}"
            )

        print("\n--- EXTERNAL DOMAINS ---")

        for domain in data.get(
            "external_domains",
            []
        ):

            print(
                f"  {domain}"
            )

        print("\n--- FINDINGS ---")

        for finding in data.get(
            "findings",
            []
        ):

            print(
                f"[!] {finding}"
            )