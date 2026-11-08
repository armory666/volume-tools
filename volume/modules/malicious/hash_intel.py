from volume.core import config, indicators, sources
from volume.core.module_base import BaseModule


class HashIntel(BaseModule):
    @property
    def id(self):
        return "hash_intel"

    @property
    def label(self):
        return "Hash / Malware Intel"

    @property
    def category(self):
        return "MALICIOUS"

    @property
    def description(self):
        return "Hash identification, VirusTotal and MalwareBazaar malware intel"

    @property
    def min_tier(self):
        return "PREMIUM"

    @property
    def order(self):
        return 70

    @property
    def credit_cost(self):
        return 2

    @property
    def requires_key(self):
        return ("vt",)

    @property
    def inputs(self):
        return ["hash"]

    def run(self, case, **kwargs):
        file_hash = (kwargs.get("hash") or "").strip().lower()
        if not file_hash:
            return self.result(rows=[("Error", "No hash provided")], status="error")

        kind = indicators.hash_type(file_hash)
        rows = [("Hash", file_hash), ("Length", str(len(file_hash)))]
        if kind:
            rows.append(("Type", kind))
        else:
            rows.append(("Type", "unknown / not a hex digest"))
            return self.result(
                title="Hash Intel",
                rows=rows + [("Error", "Provide an MD5/SHA-1/SHA-256/SHA-512 hex digest")],
                status="error",
            )

        risk = 0
        detections = 0
        families = []

        # VirusTotal
        vt_key = config.get_key("vt")
        if vt_key:
            response = sources.vt_file(file_hash, vt_key)
            if response.get("status") == "ok":
                data = (response.get("data") or {}).get("data") or {}
                attributes = data.get("attributes") or {}
                stats = attributes.get("last_analysis_stats") or {}
                malicious = int(stats.get("malicious") or 0)
                suspicious = int(stats.get("suspicious") or 0)
                harmless = int(stats.get("harmless") or 0)
                total = malicious + suspicious + harmless + int(stats.get("undetected") or 0)
                detections = malicious
                rows.append(("VirusTotal", f"{malicious} malicious / {suspicious} suspicious / {total} engines"))
                if malicious:
                    risk += min(70, 25 + malicious * 2)
                names = attributes.get("meaningful_name") or attributes.get("names") or []
                if isinstance(names, list):
                    names = names[:5]
                    if names:
                        rows.append(("Names", ", ".join(str(n) for n in names)[:220]))
                else:
                    rows.append(("Name", str(names)[:220]))
                threat = (attributes.get("popular_threat_classification") or {})
                label = threat.get("suggested_threat_label")
                if label:
                    families.append(label)
                    rows.append(("Threat label", label))
                classes = threat.get("popular_threat_category") or []
                if classes:
                    rows.append(("Categories", ", ".join(c.get("value", "?") for c in classes[:5])))
                tags = attributes.get("tags") or []
                if tags:
                    rows.append(("VT tags", ", ".join(str(t) for t in tags[:12])))
                rows.append(("First seen", str(attributes.get("first_submission_date", "-"))))
                rows.append(("File type", str(attributes.get("type_description", "-"))))
                rows.append(("Size", f"{int(attributes.get('size') or 0):,} bytes"))
            elif response.get("status") == "not_found":
                rows.append(("VirusTotal", "hash not in dataset"))
            else:
                rows.append(("VirusTotal", f"error · {response.get('error') or response.get('status')}"))
        else:
            rows.append(("VirusTotal", "not configured (VT_API_KEY)"))

        # MalwareBazaar
        mb_key = config.get_key("abusech")
        response = sources.malwarebazaar_hash(file_hash, mb_key)
        data = response.get("data") if response.get("status") == "ok" else None
        if isinstance(data, dict) and data.get("query_status") == "ok":
            samples = data.get("data") or []
            if samples:
                sample = samples[0]
                rows.append(("MalwareBazaar", "KNOWN SAMPLE"))
                risk += 40
                rows.append(("Signature", str(sample.get("signature") or "-")))
                rows.append(("File type", str(sample.get("file_type") or "-")))
                rows.append(("First seen", str(sample.get("first_seen") or "-")))
                tags = sample.get("tags") or []
                if tags:
                    rows.append(("Tags", ", ".join(str(t) for t in tags[:12])))
        elif isinstance(data, dict) and data.get("query_status") == "hash_not_found":
            rows.append(("MalwareBazaar", "not listed"))
        else:
            rows.append(("MalwareBazaar", "unavailable"))

        risk = min(100, risk)
        verdict = "MALICIOUS" if detections or risk >= 40 else "no detections"
        rows.append(("Verdict", verdict))
        rows.append(("Risk", f"{indicators.risk_label(risk)} ({risk}/100)"))

        return self.result(
            title=f"Hash Intel: {file_hash[:24]}…",
            source="VirusTotal + MalwareBazaar",
            confidence="high" if (vt_key or detections) else "medium",
            rows=rows,
            risk=risk,
            detections=detections,
            families=families,
        )

    def pivots(self, result):
        file_hash = result.get("title", "").replace("Hash Intel: ", "").rstrip("…").strip()
        return [("hash", file_hash)] if file_hash else []
