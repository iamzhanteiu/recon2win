"""sensitive_ext — shared constants for file-extension focus lists.

Two lists are exposed:
  SENSITIVE_EXT: file extensions that dirsearch / waymore should hunt for.
  STATIC_EXT:    extensions to strip from the "dynamic URL" list because
                 they are obvious static assets and would only add noise.
"""
from __future__ import annotations

# Full list from the spec (diagram node AaWYI2kdqzjv3vxHPwRm-76).
# Leading dots are kept; "docker-compose.yml" entries have no leading dot.
SENSITIVE_EXT: list[str] = [
    ".bak", ".backup", ".old", ".zip", ".tar", ".tar.gz", ".rar", ".7z",
    ".gzip", ".tar.bz2", ".tgz", ".gz", ".war", ".jar",
    ".conf", ".config", ".cfg", ".ini", ".xml", ".yaml", ".yml", ".properties",
    ".env", ".env.local", ".env.production", ".env.development", ".env.example",
    ".htaccess", ".htpasswd", ".web.config", ".gradle", ".maven",
    ".php", ".asp", ".aspx", ".jsp", ".py", ".rb", ".js", ".ts", ".go",
    ".java", ".cs", ".cpp", ".c", ".sh", ".bash", ".sql", ".pl",
    ".swift", ".kotlin", ".scala",
    ".key", ".pem", ".pub", ".ppk", ".p12", ".pfx", ".cer", ".crt",
    ".pkey", ".rsa", ".dsa", ".pass", ".pwd", ".credentials", ".secret",
    ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".dbf", ".dump",
    ".git", ".gitignore", ".gitconfig", ".github", ".svn", ".hg", ".bzr",
    ".patch", ".diff", ".changelog",
    ".doc", ".docx", ".pdf", ".txt", ".md", ".readme", ".todo", ".notes",
    ".history", ".release",
    ".log", ".logs", ".error", ".warning", ".debug", ".trace",
    ".access_log", ".error_log", ".audit",
    ".aws", ".boto", ".s3cfg", ".terraform", ".tfstate", ".tfvars",
    ".cloudformation", ".azurerm",
    ".json", ".wsdl", ".wadl", ".swagger", ".openapi", ".graphql",
    ".postman_collection",
    ".dockerfile", "docker-compose.yml", ".gitlab-ci.yml", ".travis.yml",
    ".jenkins", ".circleci", ".bitbucket-pipelines.yml", ".env.ci",
    ".package.json", ".pom.xml", ".requirements.txt", ".gemfile", ".pipfile",
    ".npm-debug.log", ".yarn-error.log",
    ".cache", ".tmp", ".temp", ".swp", ".swo", ".swx", ".bak~",
    ".DS_Store", ".thumbs.db", "._*", ".dockerignore",
    "docker-compose.override.yml", "docker-compose.prod.yml",
    ".p7b", ".csr", ".cer.pem", ".key.pem", ".well-known",
    ".cvs", ".ftp", ".sshconfig", ".pac",".js.map"
]


# Extensions to strip from the "dynamic URL" list.
STATIC_EXT: list[str] = [
    ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".css", ".woff", ".woff2", ".ico",
    ".mp4", ".mp3",
]


def to_dirsearch_flag(extensions: list[str]) -> str:
    """Concatenate extensions into dirsearch's -e format (comma-separated, no spaces)."""
    # dirsearch takes a comma-separated list, e.g. -e bak,old,zip
    return ",".join(ext.lstrip(".") for ext in extensions)


def to_waymore_filter(extensions: list[str]) -> list[str]:
    """Convert to waymore's --filter-status / extension arg style.

    waymore uses --filter-status-code 200/403 etc.; for extension filtering
    we just keep the list as-is so the caller can decide.
    """
    return [e.lstrip(".") for e in extensions]
