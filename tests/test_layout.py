"""Tests for modules.layout — the processed/ path registry.

The split only pays off if two things hold: a fresh run writes the grouped
tree, and a ``--resume`` over a pre-split output tree keeps working. The
second is the one that can quietly corrupt a run — half the artefacts read
from the flat root and half written into new folders — so most of these
tests are about the fallback.
"""
from __future__ import annotations

from modules import layout
from modules.utils import create_output_structure


# ----------------------------------------------------------------------
# Registry integrity
# ----------------------------------------------------------------------
def test_every_registered_name_is_in_exactly_one_group():
    seen: dict[str, str] = {}
    for group, names in layout.GROUPS.items():
        for name in names:
            assert name not in seen, f"{name} in both {seen.get(name)} and {group}"
            seen[name] = group


def test_group_of_known_and_unknown():
    assert layout.group_of("all_urls.txt") == "corpus"
    assert layout.group_of("ffuf_urls.txt") == "sources"
    assert layout.group_of("parameterized_urls.txt") == "targets"
    assert layout.group_of("something_new.txt") is None


def test_unregistered_name_stays_at_the_processed_root(tmp_path):
    # Unknown artefacts must still resolve somewhere sane rather than raise —
    # a new stage that forgets to register just loses the grouping.
    p = layout.grouped_path(tmp_path, "brand_new.txt")
    assert p == tmp_path / "processed" / "brand_new.txt"


# ----------------------------------------------------------------------
# Fresh tree — writers build the grouped layout
# ----------------------------------------------------------------------
def test_path_places_a_new_file_in_its_group(tmp_path):
    p = layout.path(tmp_path, "all_urls.txt")
    assert p == tmp_path / "processed" / "corpus" / "all_urls.txt"


def test_path_creates_the_parent_directory(tmp_path):
    p = layout.path(tmp_path, "jsluice_urls.txt")
    assert p.parent.is_dir()


def test_path_returns_the_grouped_file_once_it_exists(tmp_path):
    p = layout.path(tmp_path, "subdomains.txt")
    p.write_text("a.x.com\n")
    assert layout.path(tmp_path, "subdomains.txt") == p


def test_create_output_structure_makes_every_group(tmp_path):
    base = create_output_structure("x.com", root=str(tmp_path))
    for group in layout.GROUPS:
        assert (base / "processed" / group).is_dir(), group


# ----------------------------------------------------------------------
# Pre-split tree — the --resume path
# ----------------------------------------------------------------------
def test_path_falls_back_to_a_legacy_flat_file(tmp_path):
    legacy = tmp_path / "processed" / "all_urls.txt"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("https://x.com/a\n")

    assert layout.path(tmp_path, "all_urls.txt") == legacy


def test_grouped_file_wins_over_a_stale_legacy_one(tmp_path):
    legacy = tmp_path / "processed" / "all_urls.txt"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("stale\n")
    grouped = layout.grouped_path(tmp_path, "all_urls.txt")
    grouped.parent.mkdir(parents=True, exist_ok=True)
    grouped.write_text("fresh\n")

    assert layout.path(tmp_path, "all_urls.txt").read_text() == "fresh\n"


def test_a_legacy_tree_is_not_half_migrated(tmp_path):
    # Reading one artefact must not push its siblings into new folders: a
    # resumed run should keep rewriting the layout it was handed.
    proc = tmp_path / "processed"
    proc.mkdir(parents=True)
    for name in ("all_urls.txt", "dynamic_urls.txt", "js_urls.txt"):
        (proc / name).write_text("x\n")

    resolved = [layout.path(tmp_path, n) for n in
                ("all_urls.txt", "dynamic_urls.txt", "js_urls.txt")]
    assert all(p.parent == proc for p in resolved)


def test_legacy_path_and_grouped_path_are_independent_of_disk(tmp_path):
    assert layout.legacy_path(tmp_path, "forms.json") == \
        tmp_path / "processed" / "forms.json"
    assert layout.grouped_path(tmp_path, "forms.json") == \
        tmp_path / "processed" / "targets" / "forms.json"


# ----------------------------------------------------------------------
# iter_known
# ----------------------------------------------------------------------
def test_iter_known_yields_only_existing_files(tmp_path):
    layout.path(tmp_path, "all_urls.txt").write_text("a\n")
    layout.path(tmp_path, "forms.json").write_text("{}\n")

    found = {(name, group) for name, group, _ in layout.iter_known(tmp_path)}
    assert ("all_urls.txt", "corpus") in found
    assert ("forms.json", "targets") in found
    assert ("ffuf_urls.txt", "sources") not in found


def test_iter_known_reports_legacy_files_too(tmp_path):
    legacy = tmp_path / "processed" / "subdomains.txt"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("a.x.com\n")

    found = {name: p for name, _, p in layout.iter_known(tmp_path)}
    assert found["subdomains.txt"] == legacy
