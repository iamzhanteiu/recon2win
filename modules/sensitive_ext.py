"""sensitive_ext — danh sách extension / file nhạy cảm dùng chung.

Ba danh sách:

  ``SENSITIVE_EXT``   — extension THẬT, thứ có nghĩa khi nối vào sau một từ:
                        ``admin`` + ``.bak`` → ``admin.bak``. Đây là thứ duy
                        nhất được phép đi vào ``dirsearch -e`` / ``ffuf -e``.

  ``SENSITIVE_FILES`` — tên file và đường dẫn đầy đủ, phải thử TRỰC TIẾP:
                        ``/.env``, ``/.git/config``, ``/docker-compose.yml``.
                        Nối chúng vào sau một từ là vô nghĩa (``admin..env``),
                        nên chúng phải đi qua **wordlist** chứ không phải cờ
                        ``-e``.

  ``STATIC_EXT``      — extension cần loại khỏi danh sách "dynamic URL" vì
                        chắc chắn là static asset, chỉ thêm nhiễu.

Vì sao phải tách: trước đây cả hai kiểu nằm chung một list rồi đổ hết vào
``-e``. Hệ quả là dirsearch thử ``admin.env`` / ``admin.docker-compose.yml``
— trong khi mục tiêu thật là ``/.env`` và ``/docker-compose.yml``, và chúng
**không bao giờ được thử**. Chế độ extension-fallback (chạy khi chưa cấu
hình wordlist) vì thế không thể tìm ra bất kỳ dotfile nào — đúng nhóm file
giá trị nhất khi đi săn.
"""
from __future__ import annotations

# ----------------------------------------------------------------------
# Extension thật — hợp lệ với ``-e``: <từ> + <ext>
# ----------------------------------------------------------------------
# Extension ghép (``.tar.gz``, ``.js.map``, ``.key.pem``) vẫn nằm đây: chúng
# hoạt động đúng khi nối sau một từ — ``backup.tar.gz``, ``app.js.map``.
SENSITIVE_EXT: list[str] = [
    # archive / backup
    ".bak", ".bak~", ".backup", ".old", ".zip", ".tar", ".tar.gz", ".rar",
    ".7z", ".gzip", ".tar.bz2", ".tgz", ".gz", ".war", ".jar",
    # config
    ".conf", ".config", ".cfg", ".ini", ".xml", ".yaml", ".yml",
    ".properties", ".env", ".gradle", ".maven",
    # source
    ".php", ".asp", ".aspx", ".jsp", ".py", ".rb", ".js", ".ts", ".go",
    ".java", ".cs", ".cpp", ".c", ".sh", ".bash", ".sql", ".pl",
    ".swift", ".kotlin", ".scala", ".js.map",
    # khoá / chứng chỉ
    ".key", ".pem", ".pub", ".ppk", ".p12", ".pfx", ".cer", ".crt",
    ".pkey", ".rsa", ".dsa", ".p7b", ".csr", ".cer.pem", ".key.pem",
    # database
    ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".dbf", ".dump",
    # tài liệu / vá
    ".patch", ".diff", ".doc", ".docx", ".pdf", ".txt", ".md",
    # log
    ".log", ".logs", ".error", ".warning", ".debug", ".trace", ".audit",
    # API
    ".json", ".wsdl", ".wadl", ".swagger", ".openapi", ".graphql",
    # tạm / editor
    ".cache", ".tmp", ".temp", ".swp", ".swo", ".swx", ".pac",
]


# ----------------------------------------------------------------------
# Tên file / đường dẫn — thử trực tiếp, KHÔNG được đưa vào ``-e``
# ----------------------------------------------------------------------
# Không có dấu ``/`` ở đầu: cả dirsearch lẫn ffuf đều tự nối vào base URL.
SENSITIVE_FILES: list[str] = [
    # biến môi trường
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.example", ".env.ci", ".env.backup",
    # version control — .git/config và .git/HEAD đáng giá hơn nhiều so với
    # việc chỉ thử mỗi thư mục .git
    ".git", ".git/config", ".git/HEAD", ".git/index", ".gitignore",
    ".gitconfig", ".github", ".svn", ".svn/entries", ".hg", ".bzr", ".cvs",
    # web server
    ".htaccess", ".htpasswd", "web.config", ".user.ini",
    # rác của hệ điều hành / editor
    ".DS_Store", "thumbs.db", ".bash_history", ".netrc", ".npmrc",
    # secret dạng file (trước đây nằm nhầm trong danh sách extension)
    ".pass", ".pwd", ".secret", ".credentials", ".sshconfig", ".ftp",
    # container / CI
    "docker-compose.yml", "docker-compose.override.yml",
    "docker-compose.prod.yml", "Dockerfile", ".dockerignore",
    ".gitlab-ci.yml", ".travis.yml", "bitbucket-pipelines.yml",
    "Jenkinsfile", ".circleci/config.yml", ".jenkins",
    # manifest phụ thuộc
    "package.json", "package-lock.json", "composer.json", "composer.lock",
    "pom.xml", "requirements.txt", "Gemfile", "Gemfile.lock", "Pipfile",
    "yarn.lock", "npm-debug.log", "yarn-error.log",
    # cloud / IaC
    ".aws/credentials", ".aws/config", ".boto", ".s3cfg",
    ".terraform", "terraform.tfstate", "terraform.tfvars",
    "cloudformation.yml", "azurerm.json",
    # ssh
    ".ssh/id_rsa", ".ssh/id_dsa", ".ssh/config", ".ssh/known_hosts",
    # khác
    ".well-known/security.txt", "postman_collection.json",
    "access_log", "error_log", "changelog", "readme", "todo", "notes",
    "history", "release",
]


# ----------------------------------------------------------------------
# Static asset — loại khỏi danh sách "dynamic URL"
# ----------------------------------------------------------------------
STATIC_EXT: list[str] = [
    # images
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".webp", ".bmp", ".avif", ".tiff", ".apng", ".cur",
    # styles + fonts
    ".css", ".scss", ".less", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    # source maps (never a target, huge, noisy)
    ".map",
    # video
    ".mp4", ".webm", ".avi", ".mov", ".flv", ".mkv", ".m4v",
    # audio
    ".mp3", ".wav", ".ogg", ".m4a", ".aac", ".flac",
    # misc static
    ".swf",
]
# NOTE: deliberately NOT here — kept for scanning/analysis:
#   .js  → jsluice/xnLinkFinder mine endpoints & secrets from it
#   .json/.xml → often API responses / sitemaps
#   .pdf/.txt  → may leak info (metadata, robots, internal notes)


def is_static_asset(url: str) -> bool:
    """True if the URL's path ends in a static-asset extension (image, font,
    css, media, source map…). Used to drop dead-weight URLs before probing
    with httpx / scanning with nuclei — never matches ``.js`` (kept for JS
    analysis). Query string is ignored (``/a.png?v=2`` still matches)."""
    if not url:
        return False
    try:
        from urllib.parse import urlsplit
        path = urlsplit(url).path.lower()
    except ValueError:
        return False
    return any(path.endswith(ext) for ext in STATIC_EXT)


def to_dirsearch_flag(extensions: list[str]) -> str:
    """Ghép extension theo định dạng ``-e`` của dirsearch (phẩy, không space).

    Chỉ nhận extension thật. Tên file lọt vào đây sẽ sinh ra những lần thử vô
    nghĩa kiểu ``admin.docker-compose.yml``; đưa chúng qua ``SENSITIVE_FILES``
    + wordlist thay vì cờ này.
    """
    return ",".join(ext.lstrip(".") for ext in extensions)


def to_wordlist_lines(files: list[str] | None = None) -> list[str]:
    """Danh sách path cho wordlist, dùng khi chưa cấu hình wordlist nào.

    Đây là cách duy nhất chạm tới ``/.env`` và ``/.git/config``: cả hai tool
    đều nối wordlist entry thẳng vào base URL, còn ``-e`` thì nối vào sau một
    từ có sẵn.
    """
    out: list[str] = []
    seen: set[str] = set()
    for f in (SENSITIVE_FILES if files is None else files):
        s = str(f).strip().lstrip("/")
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def to_waymore_filter(extensions: list[str]) -> list[str]:
    """Convert to waymore's --filter-status / extension arg style.

    waymore uses --filter-status-code 200/403 etc.; for extension filtering
    we just keep the list as-is so the caller can decide.
    """
    return [e.lstrip(".") for e in extensions]
