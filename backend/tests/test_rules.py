"""Testes das regras determinísticas (com dados de registry/OSV simulados)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.schemas.report import Issue
from app.services.osv import parse_vulnerability
from app.services.rules import (
    DependencyContext,
    apply_rules,
    levenshtein,
    rule_deprecated,
    rule_engine_conflict,
    rule_loose_range,
    rule_outdated,
    rule_suspicious,
    rule_unmaintained,
    rule_version_not_found,
    rule_vulnerabilities,
    weeks_since,
)

NOW = datetime(2026, 9, 30, tzinfo=UTC)


def iso(days_ago: int) -> str:
    """Timestamp ISO ``days_ago`` dias atrás."""
    return (NOW - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")


def make_vuln(
    vuln_id: str = "GHSA-xxxx-yyyy-zzzz",
    *,
    label: str | None = "HIGH",
    score: float | None = 7.5,
    fixed: list[str] | None = None,
    summary: str = "Prototype pollution",
) -> dict:
    """Vulnerabilidade OSV normalizada, como o analyzer produziria."""
    return {
        "id": vuln_id,
        "aliases": ["CVE-2020-8203"],
        "summary": summary,
        "severity_label": label,
        "severity_score": score,
        "fixed_versions": fixed if fixed is not None else ["4.17.21"],
        "best_reference": f"https://github.com/advisories/{vuln_id}",
        "short_id": "CVE-2020-8203",
    }


def ctx(**overrides) -> DependencyContext:
    """Contexto padrão: pacote saudável e atualizado."""
    base: dict = {
        "name": "lodash",
        "declared_version": "^4.17.15",
        "section": "dependencies",
        "found_in_registry": True,
        "latest_version": "4.17.21",
        "declared_version_exists": True,
        "resolved_version": "4.17.15",
        "latest_published_at": iso(10),
    }
    base.update(overrides)
    return DependencyContext(**base)


# ==========================================================
# Utilitários
# ==========================================================


class TestLevenshtein:
    """Distância de edição usada na detecção de typosquatting."""

    @pytest.mark.parametrize(
        "a,b,expected",
        [
            ("lodash", "lodash", 0),
            ("lodash", "lodahs", 2),
            ("react", "raect", 2),
            ("express", "expresss", 1),
            ("", "abc", 3),
            ("abc", "", 3),
            ("axios", "axois", 2),
        ],
    )
    def test_distance(self, a: str, b: str, expected: int) -> None:
        assert levenshtein(a, b) == expected


class TestWeeksSince:
    """Cálculo de idade em semanas."""

    def test_two_years_ago_is_over_threshold(self) -> None:
        assert weeks_since(iso(800), now=NOW) == 114

    def test_recent(self) -> None:
        assert weeks_since(iso(7), now=NOW) == 1

    def test_future_is_zero(self) -> None:
        assert weeks_since((NOW + timedelta(days=10)).isoformat(), now=NOW) == 0

    def test_invalid(self) -> None:
        assert weeks_since("lixo", now=NOW) is None
        assert weeks_since(None) is None


# ==========================================================
# Regras individuais
# ==========================================================


class TestRuleVersionNotFound:
    """Versão/pacote inexistente no registry."""

    def test_package_absent_from_registry(self) -> None:
        issues = rule_version_not_found(ctx(found_in_registry=False))
        assert len(issues) == 1
        assert issues[0].type == "not_found"
        assert issues[0].source == "npm_registry"
        assert "typosquatting" in issues[0].description

    def test_version_absent(self) -> None:
        issues = rule_version_not_found(
            ctx(declared_version="^9.9.9", declared_version_exists=False, latest_version="4.17.21")
        )
        assert len(issues) == 1
        assert issues[0].type == "not_found"
        assert "9.9.9" in issues[0].description
        assert "4.17.21" in issues[0].description

    def test_url_dependency_is_not_reported(self) -> None:
        issues = rule_version_not_found(
            ctx(declared_version="github:user/repo", declared_version_exists=False)
        )
        assert issues == []

    def test_healthy_package(self) -> None:
        assert rule_version_not_found(ctx()) == []


class TestRuleDeprecated:
    """Pacote depreciado."""

    def test_deprecated_with_message(self) -> None:
        issues = rule_deprecated(ctx(deprecated_message="use lodash-es instead"))
        assert len(issues) == 1
        assert issues[0].type == "deprecated"
        assert "lodash-es" in issues[0].description

    def test_not_deprecated(self) -> None:
        assert rule_deprecated(ctx()) == []


class TestRuleVulnerabilities:
    """Vulnerabilidades do OSV."""

    def test_single_vulnerability(self) -> None:
        issues = rule_vulnerabilities(ctx(vulnerabilities=[make_vuln()]))
        assert len(issues) == 1
        assert issues[0].type == "vulnerability"
        assert issues[0].source == "osv"
        assert "CVE-2020-8203" in issues[0].description
        assert "4.17.21" in issues[0].description  # versão corrigida
        assert issues[0].references[0].startswith("https://")

    def test_without_fix(self) -> None:
        issues = rule_vulnerabilities(ctx(vulnerabilities=[make_vuln(fixed=[])]))
        assert "Nenhuma versão corrigida" in issues[0].description

    def test_severity_label_and_score_included(self) -> None:
        issues = rule_vulnerabilities(ctx(vulnerabilities=[make_vuln(label="CRITICAL", score=9.8)]))
        assert "CRITICAL" in issues[0].description
        assert "9.8" in issues[0].description

    def test_no_vulnerabilities(self) -> None:
        assert rule_vulnerabilities(ctx()) == []

    def test_description_cites_resolved_version(self) -> None:
        issues = rule_vulnerabilities(
            ctx(declared_version="0.0.8", resolved_version="0.0.8", vulnerabilities=[make_vuln()])
        )
        assert "0.0.8" in issues[0].description


class TestRuleOutdated:
    """Versão defasada."""

    def test_two_majors_behind(self) -> None:
        issues, severity = rule_outdated(
            ctx(resolved_version="1.0.0", latest_version="3.2.0", declared_version="^1.0.0")
        )
        assert len(issues) == 1
        assert issues[0].type == "outdated"
        assert severity == "medium"
        assert "2" in issues[0].description

    def test_same_major_minor_gap(self) -> None:
        issues, severity = rule_outdated(ctx(resolved_version="4.16.0", latest_version="4.17.21"))
        assert len(issues) == 1
        assert severity == "low"

    def test_patch_gap_not_reported(self) -> None:
        issues, _ = rule_outdated(ctx(resolved_version="4.17.20", latest_version="4.17.21"))
        assert issues == []

    def test_up_to_date(self) -> None:
        issues, _ = rule_outdated(ctx(resolved_version="4.17.21"))
        assert issues == []

    def test_url_or_tag_skipped(self) -> None:
        issues, _ = rule_outdated(ctx(declared_version="latest", resolved_version="1.0.0"))
        assert issues == []

    def test_nonexistent_version_not_duplicated(self) -> None:
        issues, _ = rule_outdated(
            ctx(declared_version_exists=False, resolved_version="1.0.0", latest_version="3.0.0")
        )
        assert issues == []


class TestRuleUnmaintained:
    """Pacote sem manutenção há mais de 2 anos."""

    def test_over_two_years(self) -> None:
        issues = rule_unmaintained(ctx(latest_published_at=iso(900), latest_version="1.0.0"))
        assert len(issues) == 1
        assert issues[0].type == "unmaintained"
        assert "2.9" in issues[0].description or "anos" in issues[0].description

    def test_just_under_threshold_is_clean(self) -> None:
        # 100 semanas < 104
        issues = rule_unmaintained(ctx(latest_published_at=iso(700)))
        assert issues == []

    def test_abandoned_with_low_downloads(self) -> None:
        issues = rule_unmaintained(
            ctx(latest_published_at=iso(800), latest_version="1.0.0", weekly_downloads=3)
        )
        assert "abandonado" in issues[0].description

    def test_single_maintainer_warns(self) -> None:
        issues = rule_unmaintained(
            ctx(latest_published_at=iso(900), latest_version="1.0.0", maintainer_count=1)
        )
        assert "1 mantenedor" in issues[0].description

    def test_recent_release_is_clean(self) -> None:
        assert rule_unmaintained(ctx(latest_published_at=iso(5))) == []


class TestRuleLooseRange:
    """Ranges permissivos e tags móveis."""

    def test_latest_tag(self) -> None:
        issues = rule_loose_range(ctx(declared_version="latest"))
        assert len(issues) == 1
        assert issues[0].type == "loose_range"
        assert "tag móvel" in issues[0].description
        assert issues[0].source == "regra_local"

    def test_wildcard(self) -> None:
        issues = rule_loose_range(ctx(declared_version="*"))
        assert "wildcard" in issues[0].description

    def test_open_lower_bound(self) -> None:
        issues = rule_loose_range(ctx(declared_version=">=5.0.0"))
        assert "teto superior" in issues[0].description

    def test_git_url(self) -> None:
        issues = rule_loose_range(ctx(declared_version="github:node-fetch/node-fetch"))
        assert "repositório/tarball Git" in issues[0].description

    def test_caret_is_fine(self) -> None:
        assert rule_loose_range(ctx(declared_version="^4.17.15")) == []

    def test_tilde_is_fine(self) -> None:
        assert rule_loose_range(ctx(declared_version="~4.17.15")) == []

    def test_exact_is_fine(self) -> None:
        assert rule_loose_range(ctx(declared_version="4.17.15")) == []

    def test_caret_zero_is_flagged(self) -> None:
        issues = rule_loose_range(ctx(declared_version="^0.1.0"))
        assert len(issues) == 1


class TestRuleSuspicious:
    """Typosquatting e nomes suspeitos."""

    def test_typosquat_detected(self) -> None:
        issues = rule_suspicious(
            ctx(name="lodashash", declared_version="^4.0.0"), known_packages={"lodash", "lodashash"}
        )
        assert len(issues) == 1
        assert issues[0].type == "suspicious"
        assert "typosquatting" in issues[0].description
        assert issues[0].references[0].endswith("/lodash")

    def test_no_flag_when_similar_package_absent_from_project(self) -> None:
        """Imitação só é relevante se o pacote popular também está no projeto."""
        issues = rule_suspicious(ctx(name="lodashash", declared_version="^4.0.0"), known_packages={"lodashash"})
        assert issues == []

    def test_malicious_keyword(self) -> None:
        issues = rule_suspicious(ctx(name="some-keylogger-thing", declared_version="1.0.0"))
        assert len(issues) == 1
        assert "keylogger" in issues[0].description

    def test_zero_downloads_reinforces(self) -> None:
        issues = rule_suspicious(
            ctx(name="expres", declared_version="1.0.0", weekly_downloads=0),
            known_packages={"express", "expres"},
        )
        assert len(issues) == 2
        assert any("download na semana" in i.description for i in issues)

    def test_legitimate_package_is_clean(self) -> None:
        assert rule_suspicious(ctx(name="lodash"), known_packages={"lodash"}) == []


class TestRuleEngineConflict:
    """Conflito com ``engines.node`` do projeto."""

    def test_project_node_too_old(self) -> None:
        issues = rule_engine_conflict(
            ctx(engines={"node": ">=20.0.0"}, project_engine_node=">=14.0.0")
        )
        assert len(issues) == 1
        assert ">=20.0.0" in issues[0].description
        assert ">=14.0.0" in issues[0].description

    def test_compatible(self) -> None:
        issues = rule_engine_conflict(
            ctx(engines={"node": ">=16.0.0"}, project_engine_node=">=18.0.0")
        )
        assert issues == []

    def test_missing_data(self) -> None:
        assert rule_engine_conflict(ctx()) == []
        assert rule_engine_conflict(ctx(engines={"node": ">=20.0.0"})) == []


# ==========================================================
# Orquestrador
# ==========================================================


class TestApplyRules:
    """Consolidação das regras em um resultado único."""

    def test_healthy_package_is_ok(self) -> None:
        result = apply_rules(ctx(declared_version="^4.17.20", resolved_version="4.17.21"))
        assert result.severity == "ok"
        assert result.issues == []
        assert result.breaking_change_risk == "low"
        assert result.recommendation_hint == "Nenhuma ação necessária."

    def test_vulnerability_is_high(self) -> None:
        result = apply_rules(ctx(vulnerabilities=[make_vuln()]))
        assert result.severity == "high"
        assert any(i.type == "vulnerability" for i in result.issues)
        assert "critical" not in result.recommendation_hint
        assert "4.17.21" in result.recommendation_hint

    def test_critical_vulnerability(self) -> None:
        result = apply_rules(ctx(vulnerabilities=[make_vuln(label="CRITICAL", score=9.8)]))
        assert result.severity == "critical"

    def test_medium_vulnerability(self) -> None:
        result = apply_rules(ctx(vulnerabilities=[make_vuln(label="MODERATE", score=5.0)]))
        assert result.severity == "medium"

    def test_missing_package_is_critical_and_short_circuits(self) -> None:
        result = apply_rules(
            ctx(
                name="pacote-inexistente-xyz",
                found_in_registry=False,
                declared_version_exists=False,
                latest_version=None,
            )
        )
        assert result.severity == "critical"
        assert len(result.issues) == 1
        assert result.local_flags == ["pacote_inexistente"]
        assert "Remova" in result.recommendation_hint

    def test_worst_of_all_rules_wins(self) -> None:
        # "1.x" é o caso que aciona as duas regras de uma vez: tem wildcard
        # (loose_range) e está muito atrás da latest (outdated). Com "latest"
        # a regra de outdated não se aplica, porque o npm sempre resolve a
        # versão mais recente.
        result = apply_rules(
            ctx(
                declared_version="1.x",
                resolved_version="1.0.0",
                latest_version="3.0.0",
                latest_published_at=iso(900),
                deprecated_message="migrate",
            )
        )
        assert result.severity == "high"  # deprecated
        types = {i.type for i in result.issues}
        assert {"loose_range", "outdated", "unmaintained", "deprecated"} <= types

    def test_dev_dependencies_are_downgraded(self) -> None:
        critical_runtime = apply_rules(ctx(section="dependencies", vulnerabilities=[make_vuln(label="CRITICAL", score=9.8)]))
        critical_dev = apply_rules(ctx(section="devDependencies", vulnerabilities=[make_vuln(label="CRITICAL", score=9.8)]))
        assert critical_runtime.severity == "critical"
        assert critical_dev.severity == "high"

    def test_high_vulnerability_downgraded_to_medium_in_dev(self) -> None:
        result = apply_rules(ctx(section="devDependencies", vulnerabilities=[make_vuln()]))
        assert result.severity == "medium"

    def test_breaking_risk_high_for_major_jump(self) -> None:
        result = apply_rules(ctx(resolved_version="1.0.0", latest_version="4.0.0"))
        assert result.breaking_change_risk == "high"

    def test_breaking_risk_medium_for_one_major(self) -> None:
        result = apply_rules(ctx(resolved_version="1.0.0", latest_version="2.0.0"))
        assert result.breaking_change_risk == "medium"

    def test_breaking_risk_low_for_patch(self) -> None:
        result = apply_rules(ctx(resolved_version="4.17.20", latest_version="4.17.21"))
        assert result.breaking_change_risk == "low"

    def test_unfixed_vulnerability_increases_risk(self) -> None:
        result = apply_rules(
            ctx(resolved_version="4.17.21", latest_version="4.17.21", vulnerabilities=[make_vuln(fixed=[])])
        )
        assert result.breaking_change_risk == "medium"
        assert "alternativa mantida" in result.recommendation_hint

    def test_all_issues_carry_a_source(self) -> None:
        result = apply_rules(
            ctx(
                declared_version="latest",
                resolved_version="1.0.0",
                latest_version="3.0.0",
                latest_published_at=iso(900),
                deprecated_message="migrate",
                vulnerabilities=[make_vuln()],
                engines={"node": ">=20.0.0"},
                project_engine_node=">=14.0.0",
            )
        )
        valid_sources = {"osv", "npm_registry", "regra_local", "analise_ia"}
        assert result.issues
        assert all(issue.source in valid_sources for issue in result.issues)

    def test_local_flags_reflect_triggered_rules(self) -> None:
        result = apply_rules(ctx(declared_version="*", resolved_version="1.0.0", latest_version="1.0.0"))
        assert "loose_range" in result.local_flags

    def test_typosquat_sets_suspicious_matches(self) -> None:
        result = apply_rules(
            ctx(name="lodashash", declared_version="1.0.0", resolved_version="1.0.0", latest_version="1.0.0"),
            known_packages={"lodash", "lodashash"},
        )
        assert "lodash" in result.suspicious_matches
        assert result.severity == "high"

    def test_issue_types_are_valid_enum_values(self) -> None:
        result = apply_rules(
            ctx(
                declared_version="latest",
                resolved_version="1.0.0",
                latest_version="3.0.0",
                latest_published_at=iso(900),
                vulnerabilities=[make_vuln()],
            )
        )
        for issue in result.issues:
            Issue.model_validate(issue.model_dump())


class TestOsvParsing:
    """Normalização das respostas do OSV."""

    def test_parse_full_vulnerability(self) -> None:
        raw = {
            "id": "GHSA-p6mc-m468-83gg",
            "aliases": ["CVE-2020-8203"],
            "summary": "Prototype Pollution in lodash",
            "details": "Long details " * 100,
            "published": "2020-07-15T00:00:00Z",
            "modified": "2023-01-01T00:00:00Z",
            "database_specific": {"severity": "HIGH"},
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H"}],
            "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-p6mc-m468-83gg"}],
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "lodash"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "repo": "https://github.com/npm/npm",
                            "events": [{"introduced": "0"}, {"fixed": "4.17.21"}],
                        }
                    ],
                }
            ],
        }
        vuln = parse_vulnerability(raw)
        assert vuln.id == "GHSA-p6mc-m468-83gg"
        assert vuln.short_id == "CVE-2020-8203"
        assert vuln.severity_label == "high"
        assert vuln.severity_score is not None and vuln.severity_score > 5
        assert vuln.fixed_versions == ["4.17.21"]
        assert vuln.affected_ranges == ["todas < 4.17.21"]
        assert vuln.best_reference.endswith("GHSA-p6mc-m468-83gg")

    def test_parse_minimal_vulnerability(self) -> None:
        vuln = parse_vulnerability({"id": "OSV-2021-1"})
        assert vuln.id == "OSV-2021-1"
        assert vuln.short_id == "OSV-2021-1"
        assert vuln.severity_label is None
        assert vuln.fixed_versions == []
        assert vuln.best_reference == "https://osv.dev/vulnerability/OSV-2021-1"

    def test_ignores_non_npm_ecosystem(self) -> None:
        raw = {
            "id": "OSV-1",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "x"},
                    "ranges": [{"repo": "https://pypi.org", "events": [{"fixed": "1.0"}]}],
                }
            ],
        }
        assert parse_vulnerability(raw).fixed_versions == []

    def test_collects_multiple_fixed_versions(self) -> None:
        raw = {
            "id": "OSV-2",
            "affected": [
                {
                    "package": {"ecosystem": "npm"},
                    "ranges": [{"repo": "npm", "events": [{"fixed": "1.2.0"}]}],
                },
                {
                    "package": {"ecosystem": "npm"},
                    "ranges": [{"repo": "npm", "events": [{"fixed": "1.1.0"}]}],
                },
            ],
        }
        assert parse_vulnerability(raw).fixed_versions == ["1.1.0", "1.2.0"]

    def test_to_dict(self) -> None:
        data = parse_vulnerability({"id": "OSV-3", "summary": "x"}).to_dict()
        assert data["id"] == "OSV-3"
        assert "fixedVersions" in data
