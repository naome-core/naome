"""Enforce the requested repository file policy in the required quality check."""

import unittest

from check_repository_files import check, rejected


class RepositoryFileTests(unittest.TestCase):
    def test_tracked_repository_has_only_agent_markdown(self):
        check()

    def test_nested_and_case_variant_documentation_is_rejected(self):
        denied = ["README.md", "docs/install.MD", "other/notes.Markdown", "api/doc.mdx", "a/AGENTS.MD"]
        self.assertEqual(rejected(["AGENTS.md", "a/AGENTS.md", "main.rs", "notes.toml", *denied]), sorted(denied))
