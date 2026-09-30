"""Testes do parser de package.json."""

from __future__ import annotations

import json

import pytest

from app.services.package_parser import (
    DEPENDENCY_SECTIONS,
    PackageJsonParseError,
    parse_package_json,
    weeks_since,
)


class TestParseSections:
    """Cobertura das quatro seções de dependência."""

    def test_reads_all_four_sections(self) -> None:
        content = json.dumps(
            {
                "name": "proj",
                "dependencies": {"lodash": "^4.17.15"},
                "devDependencies": {"jest": "^29.0.0"},
                "peerDependencies": {"react": ">=17"},
                "optionalDependencies": {"fsevents": "~2.3.0"},
            }
        )
        parsed = parse_package_json(content)
        sections = {d.name: d.section for d in parsed.dependencies}
        assert sections == {
            "lodash": "dependencies",
            "jest": "devDependencies",
            "react": "peerDependencies",
            "fsevents": "optionalDependencies",
        }
        assert len(parsed.dependencies) == 4
        assert parsed.runtime_count == 3
        assert parsed.dev_count == 1

    def test_ordered_sections(self) -> None:
        assert DEPENDENCY_SECTIONS == (
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        )

    def test_package_in_dev_and_runtime_is_promoted(self) -> None:
        """Pacote em ambas as seções é tratado como runtime (evita alarme falso)."""
        content = json.dumps(
            {
                "name": "proj",
                "dependencies": {"lodash": "^4.17.15"},
                "devDependencies": {"lodash": "^4.17.15"},
            }
        )
        parsed = parse_package_json(content)
        assert [d.section for d in parsed.dependencies] == ["dependencies", "dependencies"]

    def test_ignores_non_object_section(self) -> None:
        content = json.dumps({"name": "proj", "dependencies": ["lodash"], "devDependencies": {"jest": "1"}})
        parsed = parse_package_json(content)
        assert [d.name for d in parsed.dependencies] == ["jest"]

    def test_skips_invalid_version_values(self) -> None:
        content = json.dumps(
            {"name": "proj", "dependencies": {"ok": "1.0.0", "nulo": None, "objeto": {"a": 1}, "vazio": "  "}}
        )
        parsed = parse_package_json(content)
        assert [d.name for d in parsed.dependencies] == ["ok"]

    def test_numeric_version_is_coerced(self) -> None:
        content = json.dumps({"name": "proj", "dependencies": {"pacote": 1.5}})
        parsed = parse_package_json(content)
        assert parsed.dependencies[0].requested_version == "1.5"


class TestProjectMetadata:
    """Metadados do projeto extraídos do manifest."""

    def test_metadata(self) -> None:
        content = json.dumps(
            {
                "name": "meu-projeto",
                "version": "2.1.0",
                "license": {"type": "Apache-2.0"},
                "engines": {"node": ">=18.0.0"},
                "dependencies": {"lodash": "1.0.0"},
            }
        )
        parsed = parse_package_json(content)
        assert parsed.name == "meu-projeto"
        assert parsed.version == "2.1.0"
        assert parsed.license == "Apache-2.0"
        assert parsed.engine_node == ">=18.0.0"

    def test_fallback_name_when_absent(self) -> None:
        parsed = parse_package_json(
            json.dumps({"dependencies": {"lodash": "1.0.0"}}), fallback_name="me-repo"
        )
        assert parsed.name == "me-repo"

    def test_string_license(self) -> None:
        parsed = parse_package_json(
            json.dumps({"name": "p", "license": "MIT", "dependencies": {"a": "1.0.0"}})
        )
        assert parsed.license == "MIT"

    def test_unique_names(self) -> None:
        content = json.dumps(
            {"name": "p", "dependencies": {"a": "1.0.0"}, "devDependencies": {"a": "1.0.0", "b": "2.0.0"}}
        )
        parsed = parse_package_json(content)
        assert parsed.unique_names == ["a", "b"]


class TestParseErrors:
    """Manifests que devem ser rejeitados."""

    def test_invalid_json(self) -> None:
        with pytest.raises(PackageJsonParseError, match="JSON inválido"):
            parse_package_json('{"name": "x",,}')

    def test_empty_file(self) -> None:
        with pytest.raises(PackageJsonParseError, match="vazio"):
            parse_package_json("   ")

    def test_not_an_object(self) -> None:
        with pytest.raises(PackageJsonParseError, match="objeto JSON"):
            parse_package_json("[1, 2, 3]")

    def test_no_dependency_sections(self) -> None:
        with pytest.raises(PackageJsonParseError, match="não possui dependências"):
            parse_package_json(json.dumps({"name": "x", "version": "1.0.0"}))

    def test_empty_dependency_sections(self) -> None:
        with pytest.raises(PackageJsonParseError, match="não possui dependências"):
            parse_package_json(json.dumps({"name": "x", "dependencies": {}}))

    def test_invalid_utf8_bytes(self) -> None:
        with pytest.raises(PackageJsonParseError, match="UTF-8"):
            parse_package_json(b"\xff\xfe\x00\x01")

    def test_too_many_dependencies(self) -> None:
        content = json.dumps(
            {"name": "x", "dependencies": {f"pkg{i}": "1.0.0" for i in range(801)}}
        )
        with pytest.raises(PackageJsonParseError, match="excede o limite"):
            parse_package_json(content)

    def test_unsupported_type(self) -> None:
        with pytest.raises(PackageJsonParseError, match="não suportado"):
            parse_package_json(123)  # type: ignore[arg-type]


class TestInputTypes:
    """O parser aceita string, bytes e dict."""

    def test_accepts_dict(self) -> None:
        parsed = parse_package_json({"name": "p", "dependencies": {"lodash": "^4.0.0"}})
        assert parsed.dependencies[0].name == "lodash"

    def test_accepts_bytes(self) -> None:
        parsed = parse_package_json(b'{"name":"p","dependencies":{"lodash":"^4.0.0"}}')
        assert parsed.dependencies[0].name == "lodash"

    def test_strips_bom(self) -> None:
        parsed = parse_package_json('\ufeff{"name":"p","dependencies":{"lodash":"^4.0.0"}}')
        assert parsed.name == "p"

    def test_serializes_to_dict(self) -> None:
        parsed = parse_package_json({"name": "p", "dependencies": {"lodash": "^4.0.0"}})
        data = parsed.to_dict()
        assert data["name"] == "p"
        assert data["totalDependencies"] == 1
        assert data["dependencies"][0]["requestedVersion"] == "^4.0.0"


class TestExampleManifest:
    """Garante que o exemplo do repositório é analisável."""

    def test_example_is_valid(self, example_manifest: str) -> None:
        parsed = parse_package_json(example_manifest, fallback_name="exemplo")
        names = set(parsed.unique_names)
        assert "lodash" in names
        assert "minimist" in names
        assert "this-package-definitely-does-not-exist-xyz123" in names
        assert parsed.engine_node == ">=14.0.0"
        assert len(parsed.dependencies) >= 15


class TestWeeksSince:
    """Cálculo de idade em semanas."""

    def test_recent(self) -> None:
        assert weeks_since("2026-09-01T00:00:00Z") == 4

    def test_old(self) -> None:
        assert weeks_since("2020-01-01T00:00:00Z") is not None

    def test_none_and_invalid(self) -> None:
        assert weeks_since(None) is None
        assert weeks_since("não-é-data") is None
        assert weeks_since("") is None
