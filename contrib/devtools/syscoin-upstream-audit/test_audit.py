#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.
"""Synthetic, in-memory regression fixtures for the provenance candidate scan."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("marker_audit", Path(__file__).with_name("audit.py"))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class MemoryOutput:
    def __init__(self, files=None, name=""):
        self.files = {} if files is None else files
        self.name = name

    def mkdir(self, **kwargs):
        pass

    def __truediv__(self, name):
        return MemoryOutput(self.files, name)

    def write_bytes(self, value):
        self.files[self.name] = value.decode('utf-8')


def compare(old, new):
    class FakeBlobs:
        def __init__(self, repo):
            pass

        def read(self, oid):
            return {"old-blob": old.encode(), "new-blob": new.encode()}[oid]

        def close(self):
            pass

    output = MemoryOutput()
    trees = [{"src/example.cpp": ("100644", oid)} for oid in ("old-blob", "new-blob")]
    with patch.object(audit, "git", side_effect=lambda repo, *args: args[1].split("^")[0].encode()), \
            patch.object(audit, "tree", side_effect=trees), \
            patch.object(audit, "Blobs", FakeBlobs), contextlib.redirect_stdout(io.StringIO()):
        audit.analyze(Path("/unused"), "old-commit", "new-commit", output)
    return json.loads(output.files["audit.json"])


class MarkerFixtures(unittest.TestCase):
    def test_explicit_nesting(self):
        text = "// SYSCOIN BEGIN\nint a;\n// SYSCOIN BEGIN\nint b;\n// SYSCOIN END\nint c;\n// SYSCOIN END\nint d;\n"
        explicit, local, nearby, issues, marks = audit.marker_map(text)
        self.assertEqual(explicit, set(range(1, 8)))
        self.assertEqual(issues, [])

    def test_unclosed_region_remains_an_issue(self):
        explicit, local, nearby, issues, marks = audit.marker_map("// SYSCOIN BEGIN\nint a;\n")
        self.assertEqual(explicit, set())
        self.assertEqual([issue["kind"] for issue in issues], ["unclosed_begin"])

    def test_legacy_bare_tag_is_bounded(self):
        explicit, local, nearby, issues, marks = audit.marker_map("// SYSCOIN\nint a;\nint b;\n")
        self.assertEqual(local, {2})
        self.assertEqual(explicit, set())

    def test_inline_comment_is_local(self):
        explicit, local, nearby, issues, marks = audit.marker_map("int a; // SYSCOIN\nint b;\n")
        self.assertEqual(local, {1})

    def test_include_paths_and_header_guards_are_not_markers(self):
        text = ('#ifndef SYSCOIN_EXAMPLE_H\n#define SYSCOIN_EXAMPLE_H\n'
                '#include "syscoin/clientversion.h"\nint unrelated;\n'
                '#endif // SYSCOIN_EXAMPLE_H\n')
        explicit, local, nearby, issues, marks = audit.marker_map(text)
        self.assertEqual(marks, [])
        self.assertEqual(explicit | local, set())

    def test_marker_words_inside_strings_are_not_markers(self):
        for text in (
            'const char* a = "// SYSCOIN BEGIN";\nint unrelated;\nconst char* b = "// SYSCOIN END";\n',
            'const char* a = R"tag(\n// SYSCOIN BEGIN\n)tag";\nint unrelated;\nconst char* b = "// SYSCOIN END";\n',
        ):
            with self.subTest(text=text):
                explicit, local, nearby, issues, marks = audit.marker_map(text)
                self.assertEqual(marks, [])
                self.assertEqual(explicit | local, set())

    def test_changed_string_cannot_self_mark_its_hunk(self):
        result = compare('const char* s = "before";\n', 'const char* s = "// SYSCOIN";\n')
        self.assertEqual([h["status"] for h in result["hunks"]], ["no_marker_candidate"])

    def test_digit_separator_does_not_extend_legacy_marker(self):
        text = "// SYSCOIN\nconst int count = 100'000;\nint unrelated = 1;\nconst int limit = 1'000;\n"
        explicit, local, nearby, issues, marks = audit.marker_map(text)
        self.assertEqual(local, {2})

    def test_comments_separate_cpp_tokens(self):
        result = compare("int value = 1;\n", "int/**/value = 1;\n")
        self.assertEqual(result["hunks"], [])
        self.assertEqual(result["inventory"][0]["hunks"], {"comment_or_format_only": 1})

    def test_multiple_explicit_markers_on_one_line_are_balanced(self):
        text = "/* SYSCOIN BEGIN */ int a; /* SYSCOIN END */\nint b;\n"
        explicit, local, nearby, issues, marks = audit.marker_map(text)
        self.assertEqual(issues, [])
        self.assertEqual(explicit, {1})

    def test_deletion_inside_explicit_region_has_context(self):
        result = compare(
            "// SYSCOIN BEGIN\nint kept;\nint removed;\n// SYSCOIN END\n",
            "// SYSCOIN BEGIN\nint kept;\n// SYSCOIN END\n",
        )
        self.assertEqual([h["status"] for h in result["hunks"]], ["explicit_removal_context"])

    def test_deletion_before_explicit_begin_is_not_covered(self):
        result = compare(
            "int removed;\n// SYSCOIN BEGIN\nint kept;\n// SYSCOIN END\n",
            "// SYSCOIN BEGIN\nint kept;\n// SYSCOIN END\n",
        )
        self.assertEqual([h["status"] for h in result["hunks"]], ["removed_upstream_code"])

    def test_unmarked_deletion_is_a_candidate(self):
        result = compare("int kept;\nint removed;\n", "int kept;\n")
        self.assertEqual([h["status"] for h in result["hunks"]], ["removed_upstream_code"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
