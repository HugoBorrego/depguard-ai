"""Testes dos endpoints HTTP com as APIs externas mockadas."""

from __future__ import annotations

import json
from collections.abc import Iterator

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from tests.test_integration import GITHUB_API, NPM, OSV, registry_doc

APP_ENV = "test"


@pytest.fixture
def client() -> Iterator[TestClient]:
    """TestClient com o app real (settings de teste, sem IA e sem token)."""
    from app.core.config import get_settings
    from app.core.security import RateLimiter
    from app.main import create_app

    settings = get_settings()
    # Garante um estado limpo entre testes
    settings.anthropic_api_key = None
    settings.github_token = None
    # `create_app()` lê o ambiente real; o healthcheck reflete esse valor.
    settings.app_env = APP_ENV

    app = create_app()
    app.state.rate_limiter = RateLimiter(limit_per_minute=1000)
    with TestClient(app) as test_client:
        yield test_client


class TestHealth:
    """GET /api/health."""

    def test_health_ok(self, client: TestClient) -> None:
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["environment"] == APP_ENV
        assert data["aiEnabled"] is False
        assert data["githubTokenConfigured"] is False
        assert "serverTime" in data

    def test_never_exposes_secrets(self, client: TestClient) -> None:
        body = client.get("/api/health").text.lower()
        assert "sk-ant" not in body
        assert "ghp_" not in body
        assert "api_key" not in body


class TestRoot:
    """Rota raiz."""

    def test_root_points_to_docs(self, client: TestClient) -> None:
        data = client.get("/").json()
        assert data["docs"] == "/docs"
        assert data["health"] == "/api/health"


@respx.mock
class TestAnalyzeUpload:
    """POST /api/analyze/upload."""

    def test_success(self, client: TestClient) -> None:
        respx.get(f"{NPM}/lodash").mock(
            return_value=httpx.Response(
                200,
                json=registry_doc(
                    "lodash",
                    ["4.17.15", "4.17.21"],
                    time_map={
                        "4.17.15": "2019-07-10T00:00:00.000Z",
                        "4.17.21": "2021-02-20T00:00:00.000Z",
                    },
                ),
            )
        )
        respx.post(f"{OSV}/querybatch").mock(
            return_value=httpx.Response(200, json={"results": [{"vulns": []}]})
        )
        manifest = {"name": "api-teste", "dependencies": {"lodash": "^4.17.15"}}
        response = client.post(
            "/api/analyze/upload",
            files={"file": ("package.json", json.dumps(manifest).encode(), "application/json")},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["project"]["name"] == "api-teste"
        assert data["project"]["source"] == "upload"
        assert data["project"]["totalDependencies"] == 1
        assert data["findings"][0]["package"] == "lodash"
        assert "X-Request-Duration" in response.headers

    def test_rejects_malformed_json(self, client: TestClient) -> None:
        response = client.post(
            "/api/analyze/upload",
            files={"file": ("package.json", b'{"name": "x",}', "application/json")},
        )
        assert response.status_code == 400
        assert "JSON inválido" in response.json()["detail"]

    def test_rejects_wrong_filename(self, client: TestClient) -> None:
        response = client.post(
            "/api/analyze/upload",
            files={"file": ("index.js", b'{"name":"x","dependencies":{"a":"1.0.0"}}', "text/plain")},
        )
        assert response.status_code == 400
        assert "package.json" in response.json()["detail"]

    def test_rejects_oversized_file(self, client: TestClient) -> None:
        payload = json.dumps({"name": "x", "dependencies": {"a": "1.0.0"}, "pad": "y" * 1_200_000}).encode()
        response = client.post("/api/analyze/upload", files={"file": ("package.json", payload, "application/json")})
        assert response.status_code == 400
        assert "muito grande" in response.json()["detail"]

    def test_rejects_manifest_without_dependencies(self, client: TestClient) -> None:
        response = client.post(
            "/api/analyze/upload",
            files={"file": ("package.json", b'{"name":"x","version":"1.0.0"}', "application/json")},
        )
        assert response.status_code == 400
        assert "dependências" in response.json()["detail"]

    def test_missing_file_field(self, client: TestClient) -> None:
        response = client.post("/api/analyze/upload", data={})
        assert response.status_code == 422


@respx.mock
class TestAnalyzeGitHub:
    """POST /api/analyze/github."""

    def test_success(self, client: TestClient) -> None:
        respx.get(f"{GITHUB_API}/repos/user/repo").mock(
            return_value=httpx.Response(200, json={"default_branch": "main", "full_name": "user/repo"})
        )
        respx.get(f"{GITHUB_API}/repos/user/repo/contents/package.json").mock(
            return_value=httpx.Response(
                200,
                text=json.dumps({"name": "repo-app", "dependencies": {"lodash": "^4.17.21"}}),
            )
        )
        respx.get(f"{NPM}/lodash").mock(
            return_value=httpx.Response(200, json=registry_doc("lodash", ["4.17.15", "4.17.21"]))
        )
        respx.post(f"{OSV}/querybatch").mock(
            return_value=httpx.Response(200, json={"results": [{"vulns": []}]})
        )

        response = client.post("/api/analyze/github", json={"url": "https://github.com/user/repo"})
        assert response.status_code == 200
        data = response.json()
        assert data["project"]["source"] == "github"
        assert data["project"]["sourceUrl"] == "https://github.com/user/repo"
        assert data["project"]["manifests"] == ["package.json"]

    @pytest.mark.parametrize(
        "url",
        [
            "https://gitlab.com/user/repo",
            "https://evil.com/user/repo",
            "file:///etc/passwd",
            "https://169.254.169.254/latest",
            "https://github.com.evil.io/user/repo",
            "http://github.com/user/repo",
            "javascript:alert(1)",
        ],
    )
    def test_rejects_ssrf_urls_with_422(self, client: TestClient, url: str) -> None:
        response = client.post("/api/analyze/github", json={"url": url})
        assert response.status_code == 422
        assert "url" in response.json()["detail"].lower()

    def test_rejects_extra_fields(self, client: TestClient) -> None:
        response = client.post(
            "/api/analyze/github",
            json={"url": "https://github.com/user/repo", "malicious": True},
        )
        assert response.status_code == 422

    def test_rejects_empty_url(self, client: TestClient) -> None:
        response = client.post("/api/analyze/github", json={"url": ""})
        assert response.status_code == 422

    def test_repository_not_found(self, client: TestClient) -> None:
        respx.get(f"{GITHUB_API}/repos/user/naoexiste").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        response = client.post("/api/analyze/github", json={"url": "https://github.com/user/naoexiste"})
        assert response.status_code == 404
        assert "não encontrado" in response.json()["detail"]

    def test_repo_without_package_json(self, client: TestClient) -> None:
        respx.get(f"{GITHUB_API}/repos/user/docs").mock(
            return_value=httpx.Response(200, json={"default_branch": "main"})
        )
        respx.get(f"{GITHUB_API}/repos/user/docs/contents/package.json").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        respx.get(f"{GITHUB_API}/repos/user/docs/git/trees/main", params={"recursive": "1"}).mock(
            return_value=httpx.Response(200, json={"tree": [{"type": "blob", "path": "README.md"}]})
        )
        response = client.post("/api/analyze/github", json={"url": "https://github.com/user/docs"})
        assert response.status_code == 404
        assert "package.json" in response.json()["detail"]


class TestRateLimit:
    """Rate limiting por IP."""

    def test_returns_429_after_limit(self) -> None:
        from app.core.security import RateLimiter
        from app.main import create_app

        app = create_app()
        app.state.rate_limiter = RateLimiter(limit_per_minute=2)
        with TestClient(app) as limited:
            codes = [
                limited.post(
                    "/api/analyze/upload",
                    files={"file": ("package.json", b'{"name":"x"}', "application/json")},
                ).status_code
                for _ in range(4)
            ]
        assert 429 in codes
        assert codes[-1] == 429


class TestCors:
    """CORS configurável."""

    def test_preflight_allows_configured_origin(self) -> None:
        from app.core.config import get_settings
        from app.main import create_app

        settings = get_settings()
        settings.cors_origins = "https://depguard.example.com"
        app = create_app()
        with TestClient(app) as cors_client:
            response = cors_client.options(
                "/api/health",
                headers={
                    "Origin": "https://depguard.example.com",
                    "Access-Control-Request-Method": "GET",
                },
            )
            assert response.status_code == 200
            assert response.headers["access-control-allow-origin"] == "https://depguard.example.com"

    def test_other_origin_is_not_allowed(self) -> None:
        from app.core.config import get_settings
        from app.main import create_app

        settings = get_settings()
        settings.cors_origins = "https://only-this.example.com"
        app = create_app()
        with TestClient(app) as cors_client:
            response = cors_client.get("/api/health", headers={"Origin": "https://evil.example.com"})
            assert "access-control-allow-origin" not in response.headers
