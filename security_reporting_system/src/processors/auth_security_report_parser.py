def parse_auth_security_report(raw_report: dict) -> dict:
    sections = raw_report.get("sections", [])

    parsed = {
        "login_location_anomalies": {
            "status": "no_activity_detected",
            "data": []
        },
        "login_failures_by_user": {
            "status": "no_activity_detected",
            "data": []
        },
        "account_lockouts": {
            "status": "no_activity_detected",
            "data": []
        }
    }

    for section in sections:
        title = section.get("title", "")
        rows = section.get("rows", [])

        if "Login Location Anomaly" in title:
            parsed["login_location_anomalies"]["data"] = rows
            parsed["login_location_anomalies"]["status"] = (
                "data_present" if rows else "no_activity_detected"
            )

        elif "Login Failures by Top Users" in title:
            parsed["login_failures_by_user"]["data"] = rows
            parsed["login_failures_by_user"]["status"] = (
                "data_present" if rows else "no_activity_detected"
            )

        elif "Account Lockouts" in title:
            parsed["account_lockouts"]["data"] = rows
            parsed["account_lockouts"]["status"] = (
                "data_present" if rows else "no_activity_detected"
            )

    return parsed
