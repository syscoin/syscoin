#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Check the generated native MSVC configuration without building C++."""

import configparser
import importlib.util
from pathlib import Path
import re
from shutil import copyfile
from tempfile import TemporaryDirectory
import unittest
from unittest import mock
import xml.etree.ElementTree as ET


class MSVCConfigTest(unittest.TestCase):
    def test_external_btc_header_command_support(self):
        build_dir = Path(__file__).resolve().parent
        spec = importlib.util.spec_from_file_location(
            "msvc_autogen", build_dir / "msvc-autogen.py")
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        generator = importlib.util.module_from_spec(spec)
        # Importing the generator must not write bytecode into the source tree.
        with mock.patch("sys.dont_write_bytecode", True):
            spec.loader.exec_module(generator)

        with TemporaryDirectory(prefix="syscoin-msvc-config-") as temporary:
            root = Path(temporary)
            source_dir = root / "src"
            config_dir = root / "build_msvc"
            source_dir.mkdir()
            config_dir.mkdir()
            copyfile(build_dir.parent / "configure.ac", root / "configure.ac")
            copyfile(build_dir / "syscoin_config.h.in",
                     config_dir / "syscoin_config.h.in")
            # The normal generator also replaces src/config/syscoin-config.h.
            # Exercise only header generation against an isolated source tree.
            with mock.patch.object(generator, "SOURCE_DIR", str(source_dir)):
                generator.parse_config_into_btc_config()
            generated_header = (config_dir / "syscoin_config.h").read_text(
                encoding="utf8")

        definitions = dict(re.findall(
            r"^#define[ \t]+(\w+)[ \t]+([^\r\n]*)$",
            generated_header, flags=re.MULTILINE))
        for macro in ("HAVE_BOOST_PROCESS", "BOOST_PROCESS_USE_STD_FS"):
            with self.subTest(macro=macro):
                self.assertEqual(
                    definitions.get(macro), "1",
                    f"{macro} must be enabled in the generated MSVC configuration")

    def test_native_functional_btc_header_command_capability(self):
        build_dir = Path(__file__).resolve().parent
        project = ET.parse(build_dir / "syscoind" / "syscoind.vcxproj")
        namespace = {"msbuild": "http://schemas.microsoft.com/developer/msbuild/2003"}
        replacements = {
            task.get("Replace"): task.get("By", "")
            for task in project.findall(
                "./msbuild:Target[@Name='AfterBuild']/"
                "msbuild:ReplaceInFile[@FilePath='$(ConfigIniOut)']",
                namespace)
        }
        token = "@ENABLE_BTC_HEADER_COMMAND_TRUE@"
        self.assertEqual(
            replacements.get(token), "",
            "Native MSVC must enable the external Bitcoin header functional tests")
        config_template = (build_dir.parent / "test" / "config.ini.in").read_text(
            encoding="utf8")
        config = configparser.ConfigParser()
        config.read_string(config_template.replace(token, replacements[token]))
        self.assertTrue(config["components"].getboolean(
            "ENABLE_BTC_HEADER_COMMAND", fallback=False))


if __name__ == "__main__":
    unittest.main()
