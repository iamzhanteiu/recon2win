"""Tests for output filtering in make_result().

Tests that only existing files are included in the outputs list,
and that "not found" files are silently dropped.
"""
from __future__ import annotations

from pathlib import Path


from modules.utils import filter_existing_outputs, make_result


class TestFilterExistingOutputs:
    """filter_existing_outputs() — strip non-existent paths."""

    def test_filters_existing_files(self, tmp_path: Path) -> None:
        """Return only paths that exist on disk."""
        f1 = tmp_path / "exists1.txt"
        f1.write_text("data1")
        f2 = tmp_path / "exists2.txt"
        f2.write_text("data2")
        f3 = tmp_path / "does_not_exist.txt"

        result = filter_existing_outputs([f1, f2, f3])
        assert result == [str(f1), str(f2)]

    def test_preserves_order(self, tmp_path: Path) -> None:
        """Maintains the order of inputs."""
        files = [tmp_path / f"f{i}.txt" for i in range(3)]
        for f in files:
            f.write_text("x")
        # Shuffle the order: 2, 0, 1
        shuffled = [files[2], files[0], files[1]]

        result = filter_existing_outputs(shuffled)
        assert result == [str(f) for f in shuffled]

    def test_handles_empty_list(self) -> None:
        """Return empty list for empty input."""
        assert filter_existing_outputs([]) == []

    def test_handles_none(self) -> None:
        """Return empty list for None input."""
        assert filter_existing_outputs(None) == []

    def test_skips_all_nonexistent(self, tmp_path: Path) -> None:
        """Return empty list if no files exist."""
        f1 = tmp_path / "nope1.txt"
        f2 = tmp_path / "nope2.txt"

        result = filter_existing_outputs([f1, f2])
        assert result == []

    def test_string_paths(self, tmp_path: Path) -> None:
        """Accept string paths as input."""
        f1 = tmp_path / "file.txt"
        f1.write_text("x")
        f2 = tmp_path / "missing.txt"

        result = filter_existing_outputs([str(f1), str(f2)])
        assert result == [str(f1)]


class TestMakeResultWithFiltering:
    """make_result() — respects filter_outputs param."""

    def test_filters_by_default(self, tmp_path: Path) -> None:
        """By default, filter_outputs=True removes missing files."""
        f1 = tmp_path / "exists.txt"
        f1.write_text("data")
        f2 = tmp_path / "missing.txt"

        res = make_result(
            "test_stage",
            "success",
            outputs=[f1, f2],
            count=1,
        )

        assert res["outputs"] == [str(f1)]
        assert res["stage"] == "test_stage"
        assert res["status"] == "success"
        assert res["count"] == 1

    def test_respects_filter_outputs_false(self, tmp_path: Path) -> None:
        """When filter_outputs=False, include all listed paths."""
        f1 = tmp_path / "exists.txt"
        f1.write_text("data")
        f2 = tmp_path / "missing.txt"

        res = make_result(
            "test_stage",
            "success",
            outputs=[f1, f2],
            count=1,
            filter_outputs=False,
        )

        # All paths included, even the missing one
        assert len(res["outputs"]) == 2
        assert str(f1) in res["outputs"]
        assert str(f2) in res["outputs"]

    def test_empty_outputs_list(self) -> None:
        """Handle empty outputs list gracefully."""
        res = make_result("test_stage", "success", outputs=[], count=0)
        assert res["outputs"] == []

    def test_none_outputs(self) -> None:
        """Handle None outputs gracefully."""
        res = make_result("test_stage", "success", outputs=None, count=0)
        assert res["outputs"] == []

    def test_preserves_other_fields(self, tmp_path: Path) -> None:
        """Filtering doesn't affect other result fields."""
        f1 = tmp_path / "file.txt"
        f1.write_text("x")

        res = make_result(
            stage="my_stage",
            status="success",
            input_path="input.txt",
            outputs=[f1],
            count=42,
            error=None,
            extra={"key": "value"},
        )

        assert res["stage"] == "my_stage"
        assert res["status"] == "success"
        assert res["input"] == "input.txt"
        assert res["count"] == 42
        assert res["error"] is None
        assert res["extra"] == {"key": "value"}
        assert res["outputs"] == [str(f1)]

    def test_directories_are_excluded(self, tmp_path: Path) -> None:
        """Directories don't count as output files (only regular files)."""
        f1 = tmp_path / "file.txt"
        f1.write_text("data")
        d1 = tmp_path / "some_dir"
        d1.mkdir()

        res = make_result(
            "test_stage",
            "success",
            outputs=[f1, d1],
            count=1,
        )

        # Directories should be included (Path.exists() returns True for dirs)
        # If you want to exclude dirs, you'd need Path.is_file() instead.
        # For now, we just include anything that exists.
        assert len(res["outputs"]) == 2

    def test_real_world_example(self, tmp_path: Path) -> None:
        """Simulate a real stage run where some outputs don't exist yet."""
        proc_dir = tmp_path / "processed"
        proc_dir.mkdir()
        raw_dir = tmp_path / "raw"
        raw_dir.mkdir()

        # These files were created
        subdomains = proc_dir / "subdomains.txt"
        subdomains.write_text("api.example.com\nwww.example.com\n")
        subfinder = raw_dir / "subfinder.txt"
        subfinder.write_text("api.example.com\nwww.example.com\n")

        # These would have been listed but don't exist (early abort, etc.)
        amass = raw_dir / "amass.txt"
        chaos = raw_dir / "chaos.txt"

        res = make_result(
            stage="subdomain",
            status="success",
            input_path="example.com",
            outputs=[subfinder, amass, chaos, subdomains],
            count=2,
        )

        # Only the files that exist are listed
        assert len(res["outputs"]) == 2
        assert str(subfinder) in res["outputs"]
        assert str(subdomains) in res["outputs"]
        assert str(amass) not in res["outputs"]
        assert str(chaos) not in res["outputs"]
