"""Testes de integração do pipeline com as APIs externas mockadas (respx)."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from app.core.config import Settings
from app.schemas.report import AnalysisReport
from app.services.analyzer import DependencyAnalyzer
from app.services.github import GitHubClient, GitHubPackageNotFound
from app.services.llm_analyzer import LLMAnalyzer, LLMNotConfiguredError, _extract_json, load_system_prompt
from app.services.npm_registry import NpmRegistryClient
from app.services.osv import OsvClient
from app.services.package_parser import parse_package_json

NPM = "https://registry.npmjs.org"
GITHUB_API = "https://api.github.com"
OSV = "https://api.osv.dev/v1"

pytestmark = pytest.mark.anyio


def registry_doc(
    name: str,
    versions: list[str],
    *,
    latest: str | None = None,
    deprecated: str | None = None,
    time_map: dict[str, str] | None = None,
    maintainers: list[str] | None = None,
    engines: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Monta um documento do registro npm com o mesmo formato da API real."""
    latest = latest or versions[-1]
    time_map = time_map or dict.fromkeys(versions, "2026-09-01T00:00:00.000Z")
    return {
        "name": name,
        "dist-tags": {"latest": latest},
        "time": {**time_map, "created": "2015-01-01T00:00:00.000Z", "modified": "2026-09-01T00:00:00.000Z"},
        "maintainers": [{"name": m} for m in (maintainers if maintainers is not None else ["alguem"])],
        "description": f"O pacote {name}",
        "license": "MIT",
        "repository": {"type": "git", "url": f"git+https://github.com/{name}.git"},
        "versions": {
            v: {
                "name": name,
                "version": v,
                "description": f"O pacote {name}",
                "license": "MIT",
                **({"deprecated": deprecated} if deprecated else {}),
                **({"engines": engines} if engines else {}),
                "dist": {"tarball": f"{NPM}/{name}/-/{name}-{v}.tgz"},
            }
            for v in versions
        },
    }


def build_analyzer(settings: Settings) -> DependencyAnalyzer:
    """Analyzer com clients HTTP próprios, prontos para respx."""
    return DependencyAnalyzer(
        settings,
        registry=NpmRegistryClient(http=HttpClientFactory(settings), settings=settings),
        osv=OsvClient(http=HttpClientFactory(settings), settings=settings),
        llm=LLMAnalyzer(settings),
    )


def HttpClientFactory(settings: Settings | None = None) -> Any:
    """Cria um ``HttpClient`` novo (o respx intercepta pelo transport padrão).

    Recebe os settings para que os testes não herdem os retries/backoff do
    ambiente real: assim uma falha simulada falha na hora, em vez de dormir.
    """
    from app.core.http_client import HttpClient

    if settings is None:
        return HttpClient()
    # Sem retries e com timeout curto: uma falha simulada falha na hora, em vez
    # de dormir por causa do backoff exponencial.
    fast = settings.model_copy(update={"http_max_retries": 0, "http_timeout_seconds": 5.0})
    return HttpClient(fast)


# ==========================================================
# Pipeline completo (sem IA)
# ==========================================================


class TestPipelineWithoutAi:
    """Análise completa usando apenas regras determinísticas."""

    @respx.mock
    async def test_upload_analysis_end_to_end(self, settings: Settings) -> None:
        respx.get(f"{NPM}/lodash").mock(
            return_value=httpx.Response(
                200,
                json=registry_doc(
                    "lodash",
                    ["4.17.15", "4.17.20", "4.17.21"],
                    time_map={
                        "4.17.15": "2019-07-10T00:00:00.000Z",
                        "4.17.20": "2020-08-13T00:00:00.000Z",
                        "4.17.21": "2021-02-20T00:00:00.000Z",
                    },
                ),
            )
        )
        respx.get(f"{NPM}/minimist").mock(
            return_value=httpx.Response(
                200,
                json=registry_doc("minimist", ["0.0.8", "1.2.8"], latest="1.2.8"),
            )
        )
        respx.get(f"{NPM}/pacote-inexistente-xyz-123").mock(
            return_value=httpx.Response(404, json={"error": "Not found"})
        )
        respx.post(f"{OSV}/querybatch").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "vulns": [
                                {
                                    "id": "GHSA-p6mc-m468-83gg",
                                    "aliases": ["CVE-2020-8203"],
                                    "summary": "Prototype pollution",
                                    "database_specific": {"severity": "HIGH"},
                                    "severity": [
                                        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
                                    ],
                                    "references": [
                                        {"type": "ADVISORY", "url": "https://github.com/advisories/x"}
                                    ],
                                    "affected": [
                                        {
                                            "package": {"ecosystem": "npm", "name": "lodash"},
                                            "ranges": [
                                                {
                                                    "type": "SEMVER",
                                                    "repo": "npm",
                                                    "events": [{"introduced": "0"}, {"fixed": "4.17.21"}],
                                                }
                                            ],
                                        }
                                    ],
                                }
                            ]
                        },
                        {"vulns": []},
                        {"vulns": []},
                    ]
                },
            )
        )

        manifest = json.dumps(
            {
                "name": "projeto-teste",
                "version": "1.0.0",
                "license": "MIT",
                "engines": {"node": ">=14.0.0"},
                "dependencies": {
                    "lodash": "^4.17.15",
                    "minimist": "0.0.8",
                    "pacote-inexistente-xyz-123": "^1.0.0",
                },
                "devDependencies": {"lodash.debounce": "latest"},
            }
        )
        parsed = parse_package_json(manifest, fallback_name="projeto-teste")
        report = await build_analyzer(settings).analyze_manifests(
            [parsed], source="upload", source_url=None
        )

        assert isinstance(report, AnalysisReport)
        assert report.project.name == "projeto-teste"
        assert report.project.totalDependencies == 4
        assert report.project.runtimeDependencies == 3
        assert report.project.devDependencies == 1
        assert report.meta.aiEnabled is False
        assert report.meta.aiBatches == 0
        assert report.meta.durationMs >= 0

        by_name = {f.package: f for f in report.findings}

        # lodash: CVE de severidade alta
        lodash = by_name["lodash"]
        assert lodash.severity in {"high", "critical"}
        assert lodash.latestVersion == "4.17.21"
        assert lodash.resolvedVersion == "4.17.21"
        assert any(i.type == "vulnerability" and i.source == "osv" for i in lodash.issues)
        assert lodash.breakingChangeRisk in {"low", "medium", "high"}
        assert "4.17.21" in lodash.recommendation

        # minimist: defasado, sem CVE
        minimist = by_name["minimist"]
        assert minimist.latestVersion == "1.2.8"
        assert any(i.type == "outdated" for i in minimist.issues)

        # pacote inexistente
        missing = by_name["pacote-inexistente-xyz-123"]
        assert missing.severity == "critical"
        assert any(i.type == "not_found" for i in missing.issues)

        # dev dependency com tag móvel
        debounce = by_name["lodash.debounce"]
        assert debounce.isDevDependency is True
        assert debounce.severity in {"low", "medium"}

        # sumário bate com os achados
        assert report.summary.total == 4
        assert (
            report.summary.critical
            + report.summary.high
            + report.summary.medium
            + report.summary.low
            + report.summary.ok
            == len(report.findings)
        )

        # contrato de origem dos achados
        valid_sources = {"osv", "npm_registry", "regra_local", "analise_ia"}
        assert all(issue.source in valid_sources for f in report.findings for issue in f.issues)

    @respx.mock
    async def test_report_serializes_to_expected_json(self, settings: Settings) -> None:
        respx.get(f"{NPM}/lodash").mock(
            return_value=httpx.Response(200, json=registry_doc("lodash", ["4.17.15", "4.17.21"]))
        )
        respx.post(f"{OSV}/querybatch").mock(return_value=httpx.Response(200, json={"results": [{"vulns": []}]}))

        parsed = parse_package_json(json.dumps({"name": "p", "dependencies": {"lodash": "4.17.21"}}))
        report = await build_analyzer(settings).analyze_manifests([parsed], source="upload", source_url=None)

        data = json.loads(report.model_dump_json())
        # chaves exigidas pelo contrato do enunciado
        assert set(data) >= {"project", "summary", "findings", "meta"}
        assert {"name", "totalDependencies"} <= set(data["project"])
        assert {"critical", "high", "medium", "low", "ok"} <= set(data["summary"])
        finding = data["findings"][0]
        assert {
            "package",
            "requestedVersion",
            "resolvedVersion",
            "latestVersion",
            "severity",
            "issues",
            "recommendation",
            "breakingChangeRisk",
        } <= set(finding)
        assert finding["severity"] in {"critical", "high", "medium", "low", "ok"}
        assert finding["breakingChangeRisk"] in {"low", "medium", "high"}

    @respx.mock
    async def test_registry_outage_degrades_gracefully(self, settings: Settings) -> None:
        """Se o registry cai, a análise continua com as regras locais."""
        respx.get(f"{NPM}/lodash").mock(side_effect=httpx.ConnectError("sem rede"))
        respx.post(f"{OSV}/querybatch").mock(return_value=httpx.Response(200, json={"results": [{"vulns": []}]}))

        parsed = parse_package_json(json.dumps({"name": "p", "dependencies": {"lodash": "^4.0.0"}}))
        report = await build_analyzer(settings).analyze_manifests([parsed], source="upload", source_url=None)

        assert report.project.totalDependencies == 1
        assert report.findings[0].latestVersion is None
        assert report.meta.warnings  # avisou sobre a falha

    @respx.mock
    async def test_osv_outage_degrades_gracefully(self, settings: Settings) -> None:
        respx.get(f"{NPM}/lodash").mock(
            return_value=httpx.Response(200, json=registry_doc("lodash", ["4.17.15", "5.0.0"]))
        )
        respx.post(f"{OSV}/querybatch").mock(side_effect=httpx.ConnectError("osv fora"))

        parsed = parse_package_json(json.dumps({"name": "p", "dependencies": {"lodash": "4.17.15"}}))
        report = await build_analyzer(settings).analyze_manifests([parsed], source="upload", source_url=None)

        assert "outdated" in {i.type for i in report.findings[0].issues}  # os achados locais sobrevivem
        assert any("OSV" in w or "vulnerabilidades" in w for w in report.meta.warnings)

    @respx.mock
    async def test_range_resolving_existing_base_is_not_not_found(self, settings: Settings) -> None:
        """`^4.17.15` existe: a faixa aponta para versões publicadas de verdade.

        O registry publica a chave ``4.17.15``, nunca ``^4.17.15``. Consultar a
        string crua faria toda dependência com faixa parecer inexistente.
        """
        respx.get(f"{NPM}/lodash").mock(
            return_value=httpx.Response(200, json=registry_doc("lodash", ["4.17.15", "4.17.21"]))
        )
        respx.post(f"{OSV}/querybatch").mock(return_value=httpx.Response(200, json={"results": [{"vulns": []}]}))

        parsed = parse_package_json(json.dumps({"name": "p", "dependencies": {"lodash": "^4.17.15"}}))
        report = await build_analyzer(settings).analyze_manifests([parsed], source="upload", source_url=None)

        finding = report.findings[0]
        assert "not_found" not in {i.type for i in finding.issues}
        # A faixa já aceita a latest, então instalar hoje não é estar atrasado.
        assert "outdated" not in {i.type for i in finding.issues}
        assert finding.resolvedVersion == "4.17.21"

    @respx.mock
    async def test_range_satisfiable_by_nothing_is_not_found(self, settings: Settings) -> None:
        """Faixa que nenhuma versão publicada satisfaz continua sendo not_found."""
        respx.get(f"{NPM}/lodash").mock(
            return_value=httpx.Response(200, json=registry_doc("lodash", ["4.17.15", "4.17.21"]))
        )
        respx.post(f"{OSV}/querybatch").mock(return_value=httpx.Response(200, json={"results": [{"vulns": []}]}))

        parsed = parse_package_json(json.dumps({"name": "p", "dependencies": {"lodash": "^9.0.0"}}))
        report = await build_analyzer(settings).analyze_manifests([parsed], source="upload", source_url=None)

        assert "not_found" in {i.type for i in report.findings[0].issues}

    @respx.mock
    async def test_exact_version_in_a_range_is_resolved_and_flagged(self, settings: Settings) -> None:
        """Versão exata e desatualizada de verdade: existe, mas não é a mais nova."""
        respx.get(f"{NPM}/lodash").mock(
            return_value=httpx.Response(200, json=registry_doc("lodash", ["4.17.15", "5.0.0"]))
        )
        respx.post(f"{OSV}/querybatch").mock(return_value=httpx.Response(200, json={"results": [{"vulns": []}]}))

        parsed = parse_package_json(json.dumps({"name": "p", "dependencies": {"lodash": "4.17.15"}}))
        report = await build_analyzer(settings).analyze_manifests([parsed], source="upload", source_url=None)

        finding = report.findings[0]
        assert "not_found" not in {i.type for i in finding.issues}
        assert "outdated" in {i.type for i in finding.issues}
        assert finding.resolvedVersion == "4.17.15"

    @respx.mock
    async def test_stream_emits_all_steps(self, settings: Settings) -> None:
        from app.services.analyzer import PROGRESS_STEPS

        respx.get(f"{NPM}/lodash").mock(
            return_value=httpx.Response(200, json=registry_doc("lodash", ["4.17.15", "4.17.21"]))
        )
        respx.post(f"{OSV}/querybatch").mock(return_value=httpx.Response(200, json={"results": [{"vulns": []}]}))

        parsed = parse_package_json(json.dumps({"name": "p", "dependencies": {"lodash": "^4.17.15"}}))
        analyzer = build_analyzer(settings)

        steps: list[str] = []
        progresses: list[float] = []
        final = None
        async for step, progress, result in analyzer.stream_analysis(
            [parsed], source="upload", source_url=None
        ):
            steps.append(step)
            progresses.append(progress)
            if result is not None:
                final = result

        assert steps == PROGRESS_STEPS
        assert progresses == sorted(progresses)
        assert progresses[-1] == 1.0
        assert final is not None and isinstance(final, AnalysisReport)

    @respx.mock
    async def test_cache_avoids_second_request(self, settings: Settings) -> None:
        route = respx.get(f"{NPM}/lodash").mock(
            return_value=httpx.Response(200, json=registry_doc("lodash", ["4.17.15", "4.17.21"]))
        )
        respx.post(f"{OSV}/querybatch").mock(
            side_effect=[
                httpx.Response(200, json={"results": [{"vulns": []}]}),
                httpx.Response(200, json={"results": [{"vulns": []}]}),
            ]
        )
        analyzer = build_analyzer(settings)
        manifest = json.dumps({"name": "p", "dependencies": {"lodash": "^4.17.15"}})

        for _ in range(2):
            parsed = parse_package_json(manifest)
            await analyzer.analyze_manifests([parsed], source="upload", source_url=None)

        assert route.call_count == 1  # segunda análise veio do cache


# ==========================================================
# GitHub
# ==========================================================


class TestGitHubClient:
    """Descoberta de manifestos no repositório."""

    @respx.mock
    async def test_finds_root_manifest(self, settings: Settings) -> None:
        respx.get(f"{GITHUB_API}/repos/user/repo").mock(
            return_value=httpx.Response(200, json={"default_branch": "main", "full_name": "user/repo"})
        )
        contents = respx.get(f"{GITHUB_API}/repos/user/repo/contents/package.json").mock(
            return_value=httpx.Response(
                200,
                text=json.dumps({"name": "repo-projeto", "dependencies": {"lodash": "^4.0.0"}}),
                headers={"content-type": "application/json"},
            )
        )
        ref, branch, manifests = await GitHubClient(settings=settings).find_manifests(
            "https://github.com/user/repo"
        )
        assert branch == "main"
        assert ref.full_name == "user/repo"
        assert len(manifests) == 1
        assert manifests[0].is_monorepo_root is True
        assert manifests[0].url == "https://raw.githubusercontent.com/user/repo/main/package.json"
        assert contents.called

    @respx.mock
    async def test_finds_monorepo_packages(self, settings: Settings) -> None:
        respx.get(f"{GITHUB_API}/repos/user/mono").mock(
            return_value=httpx.Response(200, json={"default_branch": "trunk"})
        )
        respx.get(f"{GITHUB_API}/repos/user/mono/contents/package.json").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        respx.get(f"{GITHUB_API}/repos/user/mono/git/trees/trunk", params={"recursive": "1"}).mock(
            return_value=httpx.Response(
                200,
                json={
                    "tree": [
                        {"type": "blob", "path": "package.json"},
                        {"type": "blob", "path": "packages/api/package.json"},
                        {"type": "blob", "path": "packages/web/package.json"},
                        {"type": "blob", "path": "node_modules/foo/package.json"},
                    ]
                },
            )
        )
        respx.get(f"{GITHUB_API}/repos/user/mono/contents/packages/api/package.json").mock(
            return_value=httpx.Response(
                200,
                text=json.dumps({"name": "@mono/api", "dependencies": {"express": "^4.0.0"}}),
            )
        )
        respx.get(f"{GITHUB_API}/repos/user/mono/contents/packages/web/package.json").mock(
            return_value=httpx.Response(
                200,
                text=json.dumps({"name": "@mono/web", "devDependencies": {"vite": "^5.0.0"}}),
            )
        )

        _ref, _branch, manifests = await GitHubClient(settings=settings).find_manifests(
            "https://github.com/user/mono"
        )
        paths = [m.path for m in manifests]
        assert "packages/api/package.json" in paths
        assert "packages/web/package.json" in paths
        assert not any("node_modules" in p for p in paths)

    @respx.mock
    async def test_raises_when_no_package_json(self, settings: Settings) -> None:
        respx.get(f"{GITHUB_API}/repos/user/vazio").mock(
            return_value=httpx.Response(200, json={"default_branch": "main"})
        )
        respx.get(f"{GITHUB_API}/repos/user/vazio/contents/package.json").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        respx.get(f"{GITHUB_API}/repos/user/vazio/git/trees/main", params={"recursive": "1"}).mock(
            return_value=httpx.Response(200, json={"tree": [{"type": "blob", "path": "README.md"}]})
        )
        with pytest.raises(GitHubPackageNotFound, match="package.json"):
            await GitHubClient(settings=settings).find_manifests("https://github.com/user/vazio")

    @respx.mock
    async def test_private_repo_returns_404_message(self, settings: Settings) -> None:
        from app.services.github import GitHubError

        respx.get(f"{GITHUB_API}/repos/user/privado").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        with pytest.raises(GitHubError) as exc_info:
            await GitHubClient(settings=settings).find_manifests("https://github.com/user/privado")
        assert exc_info.value.status_code == 404
        assert "GITHUB_TOKEN" in (exc_info.value.hint or "")

    @respx.mock
    async def test_uses_token_when_configured(self) -> None:
        from app.core.config import Settings as S
        from app.core.security import parse_github_url

        cfg = S(github_token="ghp_fake_token_123", app_env="test")
        route = respx.get(f"{GITHUB_API}/repos/user/repo").mock(
            return_value=httpx.Response(200, json={"default_branch": "main"})
        )
        client = GitHubClient(settings=cfg)
        assert client.authenticated is True
        await client.get_default_branch(parse_github_url("https://github.com/user/repo"))
        assert route.calls[0].request.headers["authorization"] == "Bearer ghp_fake_token_123"

    @respx.mock
    async def test_no_auth_header_without_token(self, settings: Settings) -> None:
        from app.core.security import parse_github_url

        route = respx.get(f"{GITHUB_API}/repos/user/repo").mock(
            return_value=httpx.Response(200, json={"default_branch": "main"})
        )
        client = GitHubClient(settings=settings)
        assert client.authenticated is False
        await client.get_default_branch(parse_github_url("https://github.com/user/repo"))
        assert "authorization" not in route.calls[0].request.headers


# ==========================================================
# Registry npm
# ==========================================================


class TestNpmRegistry:
    """Parsing dos metadados do registry."""

    @respx.mock
    async def test_metadata_extraction(self, settings: Settings) -> None:
        respx.get(f"{NPM}/lodash").mock(
            return_value=httpx.Response(
                200,
                json=registry_doc(
                    "lodash",
                    ["4.17.15", "4.17.20", "4.17.21"],
                    deprecated=None,
                    time_map={
                        "4.17.15": "2019-07-10T00:00:00.000Z",
                        "4.17.20": "2020-08-13T00:00:00.000Z",
                        "4.17.21": "2021-02-20T00:00:00.000Z",
                    },
                    maintainers=["jdalton", "mathias"],
                    engines={"node": ">=4"},
                ),
            )
        )
        client = NpmRegistryClient(settings=settings)
        meta = await client.get_package("lodash")
        assert meta is not None
        assert client.latest_version(meta) == "4.17.21"
        assert client.version_exists(meta, "4.17.15") is True
        assert client.version_exists(meta, "9.9.9") is False
        assert client.all_versions(meta) == ["4.17.15", "4.17.20", "4.17.21"]
        assert client.published_at(meta, "4.17.21") == "2021-02-20T00:00:00.000Z"
        assert client.maintainers(meta) == ["jdalton", "mathias"]
        assert client.maintainer_count(meta) == 2
        assert client.engines(meta) == {"node": ">=4"}
        assert client.license_of(meta) == "MIT"
        assert client.repository_url(meta) == "https://github.com/lodash"
        assert client.max_satisfying(meta, "^4.17.15") == "4.17.21"
        assert client.min_version(meta, "^4.17.15") == "4.17.15"
        assert client.is_deprecated(meta) is False

    @respx.mock
    async def test_deprecated_message_per_version(self, settings: Settings) -> None:
        respx.get(f"{NPM}/underscore.string").mock(
            return_value=httpx.Response(
                200,
                json=registry_doc(
                    "underscore.string",
                    ["3.3.5", "3.3.6"],
                    latest="3.3.6",
                    deprecated="underscore.string is deprecated: use lodash.template instead",
                ),
            )
        )
        client = NpmRegistryClient(settings=settings)
        meta = await client.get_package("underscore.string")
        assert meta is not None
        assert client.is_deprecated(meta) is True
        assert "lodash.template" in (client.deprecated_message(meta) or "")

    @respx.mock
    async def test_not_found_is_cached_as_negative(self, settings: Settings) -> None:
        route = respx.get(f"{NPM}/nao-existe-abc").mock(return_value=httpx.Response(404, json={}))
        client = NpmRegistryClient(settings=settings)
        for _ in range(2):
            assert await client.get_package_safe("nao-existe-abc") is None
        assert route.call_count == 1  # 404 também é cacheado

    @respx.mock
    async def test_scoped_package_encoding(self, settings: Settings) -> None:
        route = respx.get(f"{NPM}/@babel%2Fcore").mock(
            return_value=httpx.Response(200, json=registry_doc("@babel/core", ["7.20.0", "7.26.0"]))
        )
        client = NpmRegistryClient(settings=settings)
        meta = await client.get_package("@babel/core")
        assert meta is not None
        assert route.called
        assert client.latest_version(meta) == "7.26.0"

    @respx.mock
    async def test_max_satisfying_semantics(self, settings: Settings) -> None:
        respx.get(f"{NPM}/p").mock(
            return_value=httpx.Response(200, json=registry_doc("p", ["1.0.0", "1.5.0", "2.0.0", "2.5.0", "3.0.0"]))
        )
        client = NpmRegistryClient(settings=settings)
        meta = await client.get_package("p")
        assert meta is not None
        assert client.max_satisfying(meta, "^1.2.0") == "1.5.0"
        assert client.max_satisfying(meta, "~1.0.0") == "1.0.0"
        assert client.max_satisfying(meta, ">=1.0.0 <3.0.0") == "2.5.0"
        assert client.max_satisfying(meta, "2.0.0") == "2.0.0"
        assert client.max_satisfying(meta, "latest") is None
        assert client.max_satisfying(meta, "github:u/r") is None

    @respx.mock
    async def test_fetch_many_limits_and_isolates_failures(self, settings: Settings) -> None:
        respx.get(f"{NPM}/a").mock(return_value=httpx.Response(200, json=registry_doc("a", ["1.0.0"])))
        respx.get(f"{NPM}/b").mock(return_value=httpx.Response(404, json={}))
        respx.get(f"{NPM}/c").mock(side_effect=httpx.ConnectError("boom"))
        client = NpmRegistryClient(settings=settings)
        results = await client.fetch_many(["a", "b", "c"])
        assert results["a"] is not None
        assert results["b"] is None
        assert results["c"] is None


# ==========================================================
# OSV
# ==========================================================


class TestOsvClient:
    """Consultas em lote ao OSV."""

    @respx.mock
    async def test_query_many_batches(self, settings: Settings) -> None:
        route = respx.post(f"{OSV}/querybatch").mock(
            return_value=httpx.Response(
                200,
                json={"results": [{"vulns": [{"id": "OSV-1"}]}, {"vulns": []}]},
            )
        )
        client = OsvClient(settings=settings)
        results = await client.query_many([("lodash", "4.17.15"), ("express", "4.18.0")])
        assert list(results) == ["lodash@4.17.15", "express@4.18.0"]
        assert results["lodash@4.17.15"][0]["id"] == "OSV-1"
        assert results["express@4.18.0"] == []
        body = json.loads(route.calls[0].request.content)
        assert body["queries"][0] == {
            "package": {"name": "lodash", "ecosystem": "npm"},
            "version": "4.17.15",
        }

    @respx.mock
    async def test_query_batch_failure_returns_none(self, settings: Settings) -> None:
        respx.post(f"{OSV}/querybatch").mock(side_effect=httpx.ConnectError("osv"))
        client = OsvClient(settings=settings)
        results = await client.query_batch([{"package": {"name": "a", "ecosystem": "npm"}, "version": "1.0.0"}])
        assert results == [None]

    async def test_empty_input_short_circuits(self, settings: Settings) -> None:
        client = OsvClient(settings=settings)
        assert await client.query_batch([]) == []
        assert await client.query_many([]) == {}


# ==========================================================
# LLM
# ==========================================================


class TestLlmAnalyzer:
    """JSON estrito, retry e degradação sem chave."""

    async def test_disabled_without_key(self, settings: Settings) -> None:
        analyzer = LLMAnalyzer(settings)
        assert analyzer.enabled is False
        with pytest.raises(LLMNotConfiguredError, match="ANTHROPIC_API_KEY"):
            await analyzer.analyze_dependencies([])

    def test_system_prompt_exists_and_has_rules(self) -> None:
        prompt = load_system_prompt()
        assert "NÃO INVENTE" in prompt
        assert "dados insuficientes" in prompt
        assert "analise_ia" in prompt
        assert "critical" in prompt and "high" in prompt and "medium" in prompt
        assert "breaking_change_risk" in prompt
        assert len(prompt) > 1500

    def test_extract_json_from_markdown_fence(self) -> None:

        assert _extract_json('```json\n{"findings": []}\n```') == '{"findings": []}'
        assert _extract_json('{"findings": []}') == '{"findings": []}'
        assert _extract_json('Claro! {"findings": []} espero que ajude') == '{"findings": []}'

    def test_extract_json_rejects_empty(self) -> None:
        from app.services.llm_analyzer import LLMResponseError

        with pytest.raises(LLMResponseError):
            _extract_json("   ")

    def test_align_findings_requires_one_to_one(self) -> None:
        from app.schemas.llm import LLMDependencyItem, LLMFinding
        from app.services.llm_analyzer import _align_findings

        items = [
            LLMDependencyItem(package="a", requested_version="1.0.0", section="dependencies"),
            LLMDependencyItem(package="b", requested_version="1.0.0", section="dependencies"),
        ]
        good = [
            LLMFinding(package="a", severity="low"),
            LLMFinding(package="b", severity="ok"),
        ]
        assert _align_findings(good, items) is not None

        assert _align_findings([LLMFinding(package="a", severity="low")], items) is None  # faltando
        assert _align_findings([*good, LLMFinding(package="c", severity="low")], items) is None  # extra
        assert _align_findings([LLMFinding(package="a", severity="low")] * 2, items) is None  # duplicata

    def test_align_findings_reorders_to_input_order(self) -> None:
        from app.schemas.llm import LLMDependencyItem, LLMFinding
        from app.services.llm_analyzer import _align_findings

        items = [
            LLMDependencyItem(package="a", requested_version="1.0.0", section="dependencies"),
            LLMDependencyItem(package="b", requested_version="1.0.0", section="dependencies"),
        ]
        reversed_findings = [LLMFinding(package="b", severity="ok"), LLMFinding(package="a", severity="ok")]
        ordered = _align_findings(reversed_findings, items)
        assert ordered is not None
        assert [f.package for f in ordered] == ["a", "b"]

    def test_align_findings_forces_source(self) -> None:
        from app.schemas.llm import LLMDependencyItem, LLMFinding, LLMIssue
        from app.services.llm_analyzer import _align_findings

        items = [LLMDependencyItem(package="a", requested_version="1.0.0", section="dependencies")]
        findings = [
            LLMFinding(
                package="a",
                severity="high",
                issues=[LLMIssue(type="vulnerability", description="x", source="osv")],  # tipo errado de propósito
            )
        ]
        ordered = _align_findings(findings, items)
        assert ordered is not None
        assert ordered[0].issues[0].source == "analise_ia"


class TestLlmBatching:
    """Lotes, retry de JSON inválido e fusão com as regras locais."""

    def _items(self, count: int) -> list[Any]:
        from app.schemas.llm import LLMDependencyItem

        return [
            LLMDependencyItem(
                package=f"pkg{i}",
                requested_version="1.0.0",
                section="dependencies",
                latest_version="2.0.0",
            )
            for i in range(count)
        ]

    def _settings(self, **overrides: Any) -> Settings:
        base: dict = {
            "anthropic_api_key": "sk-ant-fake",
            "app_env": "test",
            "llm_batch_size": 2,
            "llm_batch_concurrency": 2,
            "http_max_retries": 0,
        }
        base.update(overrides)
        return Settings(**base)

    def _fake_client(self, responses: list[str]) -> Any:
        """Cliente Anthropic falso que devolve as respostas na ordem."""

        class FakeBlock:
            def __init__(self, text: str) -> None:
                self.text = text

        class FakeMessage:
            def __init__(self, text: str) -> None:
                self.content = [FakeBlock(text)]

        class FakeMessages:
            def __init__(self) -> None:
                self.calls: list[dict[str, Any]] = []

            async def create(self, **kwargs: Any) -> FakeMessage:
                self.calls.append(kwargs)
                index = min(len(self.calls) - 1, len(responses) - 1)
                return FakeMessage(responses[index])

        class FakeAnthropic:
            def __init__(self) -> None:
                self.messages = FakeMessages()

        return FakeAnthropic()

    async def test_batches_by_size(self) -> None:
        from app.schemas.llm import LLMFinding
        from app.services.llm_analyzer import LLMAnalyzer

        analyzer = LLMAnalyzer(self._settings(llm_batch_size=2))
        items = self._items(5)
        responses = [
            json.dumps({"findings": [{"package": p, "severity": "ok"} for p in batch]})
            for batch in (["pkg0", "pkg1"], ["pkg2", "pkg3"], ["pkg4"])
        ]
        fake = self._fake_client(responses)
        analyzer._client = fake

        results = await analyzer.analyze_dependencies(items, project_name="p")
        assert len(results) == 5
        assert analyzer.batches_sent == 3
        assert all(isinstance(f, LLMFinding) for f in results.values())
        # o system prompt foi enviado em todas as chamadas
        assert all("system" in call for call in fake.messages.calls)
        assert "NÃO INVENTE" in fake.messages.calls[0]["system"]

    async def test_retry_on_invalid_json(self) -> None:
        analyzer = LLMAnalyzer(self._settings(llm_batch_size=10))
        items = self._items(2)
        valid = json.dumps(
            {"findings": [{"package": "pkg0", "severity": "low"}, {"package": "pkg1", "severity": "ok"}]}
        )
        fake = self._fake_client(["isto não é json", valid])
        analyzer._client = fake

        results = await analyzer.analyze_dependencies(items, project_name="p")
        assert len(results) == 2
        assert len(fake.messages.calls) == 2
        # a segunda tentativa carrega o erro de validação no prompt
        assert "TENTATIVA 2" in fake.messages.calls[1]["messages"][0]["content"]

    async def test_retry_on_schema_violation(self) -> None:
        analyzer = LLMAnalyzer(self._settings(llm_batch_size=10))
        items = self._items(1)
        invalid_schema = json.dumps({"findings": [{"package": "pkg0", "severity": "catastrófico"}]})
        valid = json.dumps({"findings": [{"package": "pkg0", "severity": "medium"}]})
        fake = self._fake_client([invalid_schema, valid])
        analyzer._client = fake

        results = await analyzer.analyze_dependencies(items, project_name="p")
        assert results["pkg0"].severity == "medium"
        assert "ERRO DE VALIDAÇÃO" in fake.messages.calls[1]["messages"][0]["content"]

    async def test_gives_up_after_max_attempts(self) -> None:
        analyzer = LLMAnalyzer(self._settings(llm_batch_size=10))
        items = self._items(1)
        fake = self._fake_client(["lixo", "lixo", "lixo"])
        analyzer._client = fake

        results = await analyzer.analyze_dependencies(items, project_name="p")
        assert results == {}  # chamador mantém o resultado determinístico
        assert analyzer.failures == 1
        assert len(fake.messages.calls) == 3  # 1 original + 2 correções

    async def test_api_error_is_not_retried(self) -> None:
        analyzer = LLMAnalyzer(self._settings(llm_batch_size=10))

        class Boom:
            class messages:
                @staticmethod
                async def create(**_: Any) -> None:
                    raise RuntimeError("API indisponível")

        analyzer._client = Boom()
        results = await analyzer.analyze_dependencies(self._items(1), project_name="p")
        assert results == {}
        assert analyzer.failures == 1

    async def test_empty_input(self) -> None:
        from app.services.llm_analyzer import LLMAnalyzer

        assert await LLMAnalyzer(self._settings()).analyze_dependencies([]) == {}
