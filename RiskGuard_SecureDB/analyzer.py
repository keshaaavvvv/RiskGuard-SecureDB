import re

def analyze_sql(query):
    """Heuristic static checks only. Never executes submitted SQL."""
    q = query.strip()
    low = q.lower()
    findings = []
    def add(code, title, severity, confidence, evidence, recommendation, explanation):
        findings.append({"code":code, "title":title, "severity":severity, "confidence":confidence,
                         "evidence":evidence[:220], "recommendation":recommendation, "explanation":explanation})

    # Obvious SQL injection indicators / unsafe construction patterns.
    if re.search(r"""(['"]\s*\+\s*\w+|\bformat\s*\(|f["'].*\{.*\}|%s["']?\s*%|\.format\s*\()""", q, re.I|re.S):
        add("SQLI-001", "Possible unsafe dynamic SQL construction", "High", "Medium",
            "String concatenation, interpolation, or formatting-like syntax detected.",
            "Use parameterized queries (prepared statements); do not concatenate untrusted input.",
            "Dynamic query construction can let user-controlled data alter SQL syntax. Review the surrounding application code.")
    if re.search(r"\b(or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?", low) or re.search(r"\bor\s+1\s*=\s*1\b", low):
        add("SQLI-002", "Possible tautology / injection payload", "High", "Medium",
            "A constant comparison or boolean tautology-like expression appears in the query.",
            "Treat this as suspicious input in context; parameterize values and validate expected input types.",
            "Tautologies are often used to alter WHERE-clause logic, but legitimate queries can also contain constant comparisons.")
    if re.search(r"\b(drop|truncate)\s+(table|database|schema)\b", low):
        add("DB-001", "Destructive database statement", "Critical", "High",
            "DROP or TRUNCATE statement detected.",
            "Restrict destructive privileges, require change approval, and test only against disposable databases.",
            "These statements can remove tables or data. Their presence is not automatically a vulnerability; verify authorization and intent.")
    if re.search(r"\b(delete\s+from|update\s+\w+\s+set)\b", low) and not re.search(r"\bwhere\b", low):
        add("DB-002", "Potentially unbounded UPDATE/DELETE", "High", "High",
            "UPDATE or DELETE statement appears to lack a WHERE clause.",
            "Confirm the intended row scope; use transactions, backups, and row-count safeguards.",
            "Without a restriction, a statement may affect every row in a table.")
    if re.search(r"\bselect\s+\*", low):
        add("DATA-001", "Broad SELECT * data retrieval", "Medium", "High",
            "SELECT * detected.",
            "Select only required columns and enforce authorization for every record and field.",
            "Selecting all columns can expose unnecessary or sensitive student data and makes schema changes harder to manage.")
    if re.search(r"\b(grant\s+all|with\s+grant\s+option|superuser)\b", low):
        add("PRIV-001", "Potentially excessive database privileges", "High", "Medium",
            "Broad privilege or elevated-role syntax detected.",
            "Apply least privilege, separate read/write/admin roles, and audit grants.",
            "Excessive database privileges increase impact if an application account is compromised.")
    if re.search(r"\b(insert\s+into|update\s+\w+|select\b)", low) and re.search(r"\b(password|passwd|api[_-]?key|secret|token)\b\s*=\s*['\"][^'\"]{4,}", low):
        add("SECRET-001", "Possible hardcoded secret in query text", "High", "Medium",
            "A credential-like field appears to have a quoted literal value.",
            "Remove secrets from source/query logs, rotate exposed credentials, and use a secret manager.",
            "The analyzer cannot determine whether the literal is a real credential; verify without exposing it in reports.")
    if re.search(r"\b(select|insert|update|delete)\b", low) and re.search(r"\b(email|phone|mobile|address|student_id|reg_no|date_of_birth)\b", low):
        add("PII-001", "Student/personally identifiable data fields referenced", "Medium", "High",
            "Query references common personal or student-identifying fields.",
            "Verify purpose limitation, authorization, minimal data retrieval, and safe logging/retention.",
            "PII access is not inherently vulnerable, but it should be restricted to legitimate roles and documented purposes.")
    if re.search(r"\b(union\s+select|information_schema|sqlite_master|pg_catalog)\b", low):
        add("RECON-001", "Schema enumeration / UNION pattern", "Medium", "Medium",
            "UNION SELECT or database metadata enumeration pattern detected.",
            "Review whether this is expected administrative/reporting behavior; parameterize inputs and restrict metadata access.",
            "These patterns may occur in legitimate queries but are also common in injection testing and database reconnaissance.")
    if not findings:
        add("INFO-000", "No obvious pattern matched", "Info", "Low",
            "No configured heuristic matched this input.",
            "This is not proof of safety. Review query parameters, ORM usage, permissions, and runtime behavior.",
            "Static pattern checks have false negatives and false positives and do not execute or validate the query.")
    order = {"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}
    findings.sort(key=lambda x: order.get(x["severity"], 5))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in ["Critical","High","Medium","Low","Info"]}
    return {"summary":{"finding_count":len(findings),"severity_counts":counts,
                       "method":"Heuristic static analysis; SQL is never executed."},"findings":findings}
