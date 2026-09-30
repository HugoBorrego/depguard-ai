"""Testes da proteção anti-SSRF e da validação de upload."""

from __future__ import annotations

import time

import pytest

from app.core.security import (
    InvalidGitHubUrlError,
    InvalidPackageJsonError,
    RateLimiter,
    client_identifier,
    parse_github_url,
    validate_upload,
)


class TestParseGitHubUrlValid:
    """URLs do GitHub que devem ser aceitas."""

    @pytest.mark.parametrize(
        "url",
        [
            "https://github.com/user/repo",
            "https://github.com/user/repo/",
            "https://github.com/user/repo.git",
            "https://github.com/user/repo/tree/main/packages/api",
            "https://github.com/user/repo?tab=readme-ov-file#install",
            "https://www.github.com/user/repo",
            "https://GitHub.com/user/repo",
            "  https://github.com/user/repo  ",
            "github.com/user/repo",
            "https://github.com/user/repo/issues/123",
            "https://github.com/my-org/my_repo.js",
            "https://github.com/user-1/repo_name",
        ],
    )
    def test_accepted(self, url: str) -> None:
        ref = parse_github_url(url)
        assert ref.owner == ref.owner.strip()
        assert ref.repo and not ref.repo.endswith(".git")
        assert ref.url.startswith("https://github.com/")

    def test_specific_owner_and_repo(self) -> None:
        ref = parse_github_url("https://github.com/facebook/react.git")
        assert ref.owner == "facebook"
        assert ref.repo == "react"
        assert ref.full_name == "facebook/react"
        assert ref.api_base == "https://api.github.com/repos/facebook/react"
        assert ref.raw_base == "https://raw.githubusercontent.com/facebook/react"

    def test_url_is_canonicalized(self) -> None:
        ref = parse_github_url("https://www.github.com/user/repo/tree/main?x=1")
        assert ref.url == "https://github.com/user/repo"


class TestParseGitHubUrlSsrf:
    """Vetores de SSRF e URLs malformadas que devem ser rejeitadas."""

    @pytest.mark.parametrize(
        "url",
        [
            "https://evil.com/user/repo",
            "https://github.com.evil.com/user/repo",
            "https://api.github.com/repos/user/repo",
            "https://raw.githubusercontent.com/user/repo/main/package.json",
            "https://localhost/user/repo",
            "https://127.0.0.1/user/repo",
            "https://0.0.0.0/user/repo",
            "https://[::1]/user/repo",
            "https://169.254.169.254/latest/meta-data/",
            "https://10.0.0.5/user/repo",
            "https://192.168.1.1/user/repo",
            "https://172.16.0.1/user/repo",
            "https://metadata.google.internal/user/repo",
            "https://user:pass@github.com/user/repo",
            "https://user@github.com/user/repo",
            "file:///etc/passwd",
            "gopher://github.com:70/user",
            "dict://github.com/user",
            "http://github.com/user/repo",
            "ftp://github.com/user/repo",
            "javascript:alert(1)",
            "data:text/html,<h1>x</h1>",
        ],
    )
    def test_rejected(self, url: str) -> None:
        with pytest.raises(InvalidGitHubUrlError):
            parse_github_url(url)

    @pytest.mark.parametrize(
        "url",
        [
            "",
            "   ",
            "https://github.com",
            "https://github.com/",
            "https://github.com/user",
            "https://github.com//repo",
            "https://github.com/user/",
            "github.com",
            "https://github.com/-invalid-/repo",
            "https://github.com/user/repo with spaces",
            "https://github.com/usuário/repo",
            "a" * 400,
        ],
    )
    def test_malformed_rejected(self, url: str) -> None:
        with pytest.raises(InvalidGitHubUrlError):
            parse_github_url(url)

    def test_non_string_rejected(self) -> None:
        with pytest.raises(InvalidGitHubUrlError):
            parse_github_url(None)  # type: ignore[arg-type]

    def test_error_message_is_user_friendly(self) -> None:
        with pytest.raises(InvalidGitHubUrlError, match="github.com"):
            parse_github_url("https://gitlab.com/user/repo")

    def test_only_github_hosts_allowed(self) -> None:
        """Verifica a allowlist de hosts."""
        from app.core.security import ALLOWED_GITHUB_HOSTS

        assert frozenset({"github.com", "www.github.com"}) == ALLOWED_GITHUB_HOSTS


class TestValidateUpload:
    """Validação do package.json enviado."""

    def test_valid(self) -> None:
        raw = b'{"name":"p","dependencies":{"lodash":"^4.0.0"}}'
        upload = validate_upload("package.json", raw)
        assert upload.filename == "package.json"
        assert upload.size_bytes == len(raw)
        assert upload.parsed()["name"] == "p"

    def test_accepts_nested_filename(self) -> None:
        raw = b'{"name":"p","dependencies":{"a":"1.0.0"}}'
        upload = validate_upload("/home/user/proj/package.json", raw)
        assert upload.filename == "package.json"

    def test_strips_bom(self) -> None:
        raw = b'\xef\xbb\xbf{"name":"p","dependencies":{"a":"1.0.0"}}'
        assert validate_upload("package.json", raw).parsed()["name"] == "p"

    def test_rejects_empty(self) -> None:
        with pytest.raises(InvalidPackageJsonError, match="vazio"):
            validate_upload("package.json", b"")

    def test_rejects_wrong_filename(self) -> None:
        raw = b'{"name":"p","dependencies":{"a":"1.0.0"}}'
        with pytest.raises(InvalidPackageJsonError, match="package.json"):
            validate_upload("index.js", raw)

    def test_rejects_invalid_json(self) -> None:
        with pytest.raises(InvalidPackageJsonError, match="JSON inválido"):
            validate_upload("package.json", b'{"name": }')

    def test_rejects_json_array(self) -> None:
        with pytest.raises(InvalidPackageJsonError, match="objeto JSON"):
            validate_upload("package.json", b'[1,2,3]')

    def test_rejects_invalid_utf8(self) -> None:
        with pytest.raises(InvalidPackageJsonError, match="UTF-8"):
            validate_upload("package.json", b"\xff\xfe\x00\x00")

    def test_rejects_oversized_file(self) -> None:
        from app.core.config import Settings

        big = b'{"name":"p","dependencies":{' + b'"a":"1.0.0",' * 200 + b'"b":"1.0.0"}}'
        small = Settings(max_upload_bytes=1024, app_env="test")
        with pytest.raises(InvalidPackageJsonError, match="muito grande"):
            validate_upload("package.json", big, small)

    def test_size_limit_respects_settings(self) -> None:
        from app.core.config import Settings

        tiny = Settings(max_upload_bytes=10, app_env="test")
        with pytest.raises(InvalidPackageJsonError, match="muito grande"):
            validate_upload("package.json", b'{"name":"p","dependencies":{"a":"1.0.0"}}', tiny)

    def test_rejects_malformed_content_type(self) -> None:
        with pytest.raises(InvalidPackageJsonError):
            validate_upload("package.json", b'{"dependencies": [1,2]}')


class TestRateLimiter:
    """Rate limiting em memória com janela deslizante."""

    def test_allows_up_to_limit(self) -> None:
        limiter = RateLimiter(3)
        for _ in range(3):
            allowed, retry_after = limiter.check("1.1.1.1")
            assert allowed is True
            assert retry_after == 0

    def test_blocks_after_limit(self) -> None:
        limiter = RateLimiter(2)
        limiter.check("1.1.1.1")
        limiter.check("1.1.1.1")
        allowed, retry_after = limiter.check("1.1.1.1")
        assert allowed is False
        assert 0 < retry_after <= 60

    def test_per_key_isolation(self) -> None:
        limiter = RateLimiter(1)
        assert limiter.check("ip-a")[0] is True
        assert limiter.check("ip-b")[0] is True
        assert limiter.check("ip-a")[0] is False

    def test_window_expires(self) -> None:
        limiter = RateLimiter(1)
        assert limiter.check("ip")[0] is True
        assert limiter.check("ip")[0] is False
        # Injeta um hit antigo para simular a passagem da janela
        limiter._hits["ip"] = [time.monotonic() - 120]
        assert limiter.check("ip")[0] is True

    def test_reset(self) -> None:
        limiter = RateLimiter(1)
        limiter.check("ip")
        limiter.reset()
        assert limiter.check("ip")[0] is True


class TestClientIdentifier:
    """Extração do IP do cliente respeitando proxies."""

    def test_remote_addr(self) -> None:
        class FakeClient:
            host = "203.0.113.5"

        class FakeRequest:
            client = FakeClient()
            headers: dict[str, str] = {}

        assert client_identifier(FakeRequest()) == "203.0.113.5"

    def test_forwarded_header_wins(self) -> None:
        class FakeClient:
            host = "10.0.0.1"

        class FakeRequest:
            client = FakeClient()
            headers = {"x-forwarded-for": "198.51.100.7, 10.0.0.1"}

        assert client_identifier(FakeRequest()) == "198.51.100.7"

    def test_x_real_ip(self) -> None:
        class FakeRequest:
            client = None
            headers = {"x-real-ip": "198.51.100.9"}

        assert client_identifier(FakeRequest()) == "198.51.100.9"

    def test_unknown_fallback(self) -> None:
        class FakeRequest:
            client = None
            headers: dict[str, str] = {}

        assert client_identifier(FakeRequest()) == "unknown"
