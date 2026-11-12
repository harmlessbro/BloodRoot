import hashlib
import socket

import dns.resolver
import requests


class EmailAuditor:

    def __init__(self, email):

        self.email = email.strip().lower()

        self.domain = (
            self.email.split("@", 1)[1]
            if "@" in self.email
            else None
        )

    def check_mx(self):

        if not self.domain:
            return []

        records = []

        try:

            answers = dns.resolver.resolve(
                self.domain,
                "MX"
            )

            for record in answers:

                records.append(
                    str(record.exchange).rstrip(".")
                )

        except Exception:
            pass

        return records

    def check_txt(self):

        if not self.domain:
            return []

        records = []

        try:

            answers = dns.resolver.resolve(
                self.domain,
                "TXT"
            )

            for record in answers:

                records.append(
                    "".join(
                        record.strings
                    ).decode(
                        errors="ignore"
                    )
                )

        except Exception:
            pass

        return records

    def gravatar(self):

        digest = hashlib.md5(
            self.email.encode()
        ).hexdigest()

        url = (
            "https://www.gravatar.com/avatar/"
            + digest
            + "?d=404"
        )

        try:

            response = requests.get(
                url,
                timeout=10
            )

            return {
                "hash": digest,
                "exists": response.status_code == 200
            }

        except requests.RequestException:

            return {
                "hash": digest,
                "exists": False
            }

    def run(self):

        findings = []

        if not self.domain:

            return {
                "error": "Invalid email format",
                "findings": []
            }

        mx = self.check_mx()

        txt = self.check_txt()

        gravatar = self.gravatar()

        if mx:

            findings.append(
                "Email domain has MX records"
            )

        if gravatar["exists"]:

            findings.append(
                "Gravatar profile/avatar may be associated with email"
            )

        spf = [
            x for x in txt
            if "v=spf1" in x.lower()
        ]

        dmarc = []

        try:

            answers = dns.resolver.resolve(
                f"_dmarc.{self.domain}",
                "TXT"
            )

            for record in answers:

                value = "".join(
                    record.strings
                ).decode(
                    errors="ignore"
                )

                dmarc.append(value)

        except Exception:
            pass

        return {
            "email": self.email,
            "domain": self.domain,
            "mx": mx,
            "spf": spf,
            "dmarc": dmarc,
            "dns_txt": txt,
            "gravatar": gravatar,
            "findings": findings
        }

    def display(self, data):

        print("\n" + "=" * 65)
        print("                      EMAIL AUDIT")
        print("=" * 65)

        print(
            f"\nEmail  : {data.get('email')}"
        )

        print(
            f"Domain : {data.get('domain')}"
        )

        print("\n--- MX RECORDS ---")

        for record in data.get("mx", []):

            print(
                f"  {record}"
            )

        print("\n--- SPF ---")

        for record in data.get("spf", []):

            print(
                f"  {record}"
            )

        print("\n--- DMARC ---")

        for record in data.get("dmarc", []):

            print(
                f"  {record}"
            )

        print("\n--- GRAVATAR ---")

        gravatar = data.get(
            "gravatar",
            {}
        )

        print(
            "  Associated:"
            f" {gravatar.get('exists')}"
        )

        print("\n--- FINDINGS ---")

        for finding in data.get(
            "findings",
            []
        ):

            print(
                f"[!] {finding}"
            )