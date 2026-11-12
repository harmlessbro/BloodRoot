import requests


class UsernameScanner:

    SERVICES = {
        "GitHub":
            "https://github.com/{username}",

        "GitLab":
            "https://gitlab.com/{username}",

        "Reddit":
            "https://www.reddit.com/user/{username}/",

        "Dev.to":
            "https://dev.to/{username}",

        "PyPI":
            "https://pypi.org/user/{username}/",

        "HackerRank":
            "https://www.hackerrank.com/{username}",

        "Keybase":
            "https://keybase.io/{username}",

        "Codeberg":
            "https://codeberg.org/{username}",

        "Docker Hub":
            "https://hub.docker.com/u/{username}"
    }

    def __init__(self, username):

        self.username = username

        self.session = requests.Session()

        self.session.headers.update({
            "User-Agent": "Self-OSINT-Auditor/1.0"
        })

    def check(self, service, url):

        try:

            response = self.session.get(
                url.format(
                    username=self.username
                ),
                timeout=10,
                allow_redirects=True
            )

            return {
                "service": service,
                "status": response.status_code,
                "final_url": response.url,
                "found": response.status_code == 200
            }

        except requests.RequestException as e:

            return {
                "service": service,
                "error": str(e),
                "found": False
            }

    def run(self):

        results = []
        findings = []

        for service, url in self.SERVICES.items():

            print(
                f"[*] Checking {service}..."
            )

            result = self.check(
                service,
                url
            )

            results.append(result)

            if result.get("found"):

                findings.append(
                    f"Username found on {service}"
                )

        return {
            "username": self.username,
            "results": results,
            "findings": findings
        }

    def display(self, data):

        print("\n" + "=" * 65)
        print("                    USERNAME AUDIT")
        print("=" * 65)

        for result in data["results"]:

            service = result["service"]

            if result.get("found"):

                print(
                    f"[FOUND] {service}"
                )

                print(
                    f"        {result.get('final_url')}"
                )

            elif "status" in result:

                print(
                    f"[{result['status']}] {service}"
                )

            else:

                print(
                    f"[ERROR] {service}"
                )