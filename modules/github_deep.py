import sys
import requests
from datetime import datetime


API = "https://api.github.com"


class GitHubDeepAuditor:

    def __init__(self, username, token=None):
        self.username = username
        self.token = token

        self.session = requests.Session()

        self.session.headers.update({
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Self-OSINT-Auditor"
        })

        if token:
            self.session.headers["Authorization"] = (
                f"Bearer {token}"
            )

    def api_get(self, endpoint, params=None):

        try:

            response = self.session.get(
                API + endpoint,
                params=params,
                timeout=15
            )

            if response.status_code == 404:
                return None

            if response.status_code == 403:
                print(
                    "[!] GitHub API rate limit "
                    "or permission error."
                )
                return None

            response.raise_for_status()

            return response.json()

        except requests.RequestException as e:

            print(
                f"[!] GitHub API error: {e}"
            )

            return None

    def audit_user(self):

        return self.api_get(
            f"/users/{self.username}"
        )

    def audit_repositories(self):

        return self.api_get(
            f"/users/{self.username}/repos",
            params={
                "per_page": 100,
                "sort": "updated"
            }
        ) or []

    def audit_orgs(self):

        return self.api_get(
            f"/users/{self.username}/orgs",
            params={
                "per_page": 100
            }
        ) or []

    def audit_followers(self):

        return self.api_get(
            f"/users/{self.username}/followers",
            params={
                "per_page": 100
            }
        ) or []

    def audit_following(self):

        return self.api_get(
            f"/users/{self.username}/following",
            params={
                "per_page": 100
            }
        ) or []

    def audit_commits(self, repositories):

        results = []

        for repo in repositories:

            repo_name = repo.get("name")

            if not repo_name:
                continue

            print(
                f"[*] Checking commits: {repo_name}"
            )

            commits = self.api_get(
                f"/repos/{self.username}/{repo_name}/commits",
                params={
                    "per_page": 100
                }
            ) or []

            for commit in commits:

                commit_data = commit.get(
                    "commit",
                    {}
                )

                author = commit_data.get(
                    "author",
                    {}
                )

                committer = commit_data.get(
                    "committer",
                    {}
                )

                results.append({
                    "repository": repo_name,
                    "sha": commit.get("sha"),
                    "url": commit.get("html_url"),

                    "author_name":
                        author.get("name"),

                    "author_email":
                        author.get("email"),

                    "author_date":
                        author.get("date"),

                    "committer_name":
                        committer.get("name"),

                    "committer_email":
                        committer.get("email"),

                    "message":
                        commit_data.get("message")
                })

        return results

    def run(self):

        print(
            f"[*] Target: {self.username}"
        )

        print(
            f"[*] Started: "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

        user = self.audit_user()

        if not user:

            return {
                "error": (
                    f"GitHub user "
                    f"'{self.username}' not found"
                ),
                "findings": []
            }

        repositories = self.audit_repositories()

        orgs = self.audit_orgs()

        followers = self.audit_followers()

        following = self.audit_following()

        commits = self.audit_commits(
            repositories
        )

        # ---------------- EMAILS ----------------

        emails = {}

        for commit in commits:

            email = commit.get(
                "author_email"
            )

            if email:

                emails.setdefault(
                    email,
                    set()
                ).add(
                    commit["repository"]
                )

            email = commit.get(
                "committer_email"
            )

            if email:

                emails.setdefault(
                    email,
                    set()
                ).add(
                    commit["repository"]
                )

        email_results = []

        for email, repos in emails.items():

            email_results.append({
                "email": email,
                "repositories": sorted(repos),
                "github_noreply":
                    "noreply.github.com" in email
            })

        # ---------------- FINDINGS ----------------

        findings = []

        if user.get("email"):

            findings.append(
                "Public profile email exposed"
            )

        if user.get("location"):

            findings.append(
                "Location is present "
                "on public profile"
            )

        if user.get("company"):

            findings.append(
                "Company information exposed"
            )

        if user.get("blog"):

            findings.append(
                "External website linked "
                "from profile"
            )

        real_emails = [
            item
            for item in email_results
            if not item["github_noreply"]
        ]

        if real_emails:

            findings.append(
                f"{len(real_emails)} potentially "
                "identifying commit email(s) found"
            )

        return {
            "username": self.username,

            "profile": {
                "login": user.get("login"),
                "name": user.get("name"),
                "bio": user.get("bio"),
                "company": user.get("company"),
                "location": user.get("location"),
                "blog": user.get("blog"),
                "twitter": user.get(
                    "twitter_username"
                ),
                "public_repos": user.get(
                    "public_repos"
                ),
                "public_gists": user.get(
                    "public_gists"
                ),
                "followers": user.get(
                    "followers"
                ),
                "following": user.get(
                    "following"
                ),
                "created_at": user.get(
                    "created_at"
                ),
                "updated_at": user.get(
                    "updated_at"
                ),
                "github_id": user.get("id"),
                "node_id": user.get(
                    "node_id"
                ),
                "avatar_url": user.get(
                    "avatar_url"
                ),
                "profile_url": user.get(
                    "html_url"
                )
            },

            "repositories": [
                {
                    "name": repo.get(
                        "name"
                    ),
                    "url": repo.get(
                        "html_url"
                    ),
                    "description": repo.get(
                        "description"
                    ),
                    "language": repo.get(
                        "language"
                    ),
                    "stars": repo.get(
                        "stargazers_count"
                    ),
                    "forks": repo.get(
                        "forks_count"
                    ),
                    "created": repo.get(
                        "created_at"
                    ),
                    "updated": repo.get(
                        "updated_at"
                    ),
                    "homepage": repo.get(
                        "homepage"
                    ),
                    "topics": repo.get(
                        "topics",
                        []
                    )
                }
                for repo in repositories
            ],

            "organizations": [
                {
                    "login": org.get(
                        "login"
                    ),
                    "url": org.get(
                        "html_url"
                    )
                }
                for org in orgs
            ],

            "followers": [
                follower.get(
                    "login"
                )
                for follower in followers
            ],

            "following": [
                account.get(
                    "login"
                )
                for account in following
            ],

            "commit_emails": email_results,

            "commits": commits,

            "findings": findings
        }

    def display(self, data):

        print(
            "\n" + "=" * 65
        )

        print(
            "                  DEEP GITHUB AUDIT"
        )

        print(
            "=" * 65
        )

        if data.get("error"):

            print(
                f"\n[!] {data['error']}"
            )

            return

        profile = data["profile"]

        print("\n--- PROFILE ---")

        print(
            f"Username  : "
            f"{profile.get('login')}"
        )

        print(
            f"Name      : "
            f"{profile.get('name')}"
        )

        print(
            f"Bio       : "
            f"{profile.get('bio')}"
        )

        print(
            f"Company   : "
            f"{profile.get('company')}"
        )

        print(
            f"Location  : "
            f"{profile.get('location')}"
        )

        print(
            f"Website   : "
            f"{profile.get('blog')}"
        )

        print(
            f"Repos     : "
            f"{profile.get('public_repos')}"
        )

        print(
            f"Followers : "
            f"{profile.get('followers')}"
        )

        print(
            f"Following : "
            f"{profile.get('following')}"
        )

        print("\n--- REPOSITORIES ---")

        for repo in data[
            "repositories"
        ]:

            print(
                f"\n[{repo['name']}]"
            )

            print(
                f"  URL      : "
                f"{repo['url']}"
            )

            print(
                f"  Language : "
                f"{repo['language']}"
            )

            print(
                f"  Stars    : "
                f"{repo['stars']}"
            )

            print(
                f"  Forks    : "
                f"{repo['forks']}"
            )

            if repo["homepage"]:

                print(
                    f"  Homepage : "
                    f"{repo['homepage']}"
                )

        print("\n--- ORGANIZATIONS ---")

        for org in data[
            "organizations"
        ]:

            print(
                f"  {org['login']}"
            )

        print("\n--- COMMIT EMAILS ---")

        for item in data[
            "commit_emails"
        ]:

            if item["github_noreply"]:

                marker = "NOREPLY"

            else:

                marker = "POTENTIAL EXPOSURE"

            print(
                f"[{marker}] "
                f"{item['email']}"
            )

            for repo in item[
                "repositories"
            ]:

                print(
                    f"    └─ {repo}"
                )

        print("\n--- FINDINGS ---")

        for finding in data[
            "findings"
        ]:

            print(
                f"[!] {finding}"
            )