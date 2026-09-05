"""Dependency-free unit tests for MorpheUpdater's pure logic.

No network, no JVM, no Play API: only deterministic functions.
Run with:  uv run python -m unittest discover -s tests -v
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from morpheupdater import pb  # noqa: E402
from morpheupdater import play  # noqa: E402
from morpheupdater.daemon import (  # noqa: E402
    _enabled_archs,
    _is_mpp_candidate,
    _repo_from_url,
    combo_id,
)
from morpheupdater.pages import _compat_allows  # noqa: E402
from morpheupdater.settings import _deep_merge, short, validate_apps  # noqa: E402
from morpheupdater.tools import (  # noqa: E402
    BLOCK_RE,
    VERSION_LINE_RE,
    _gh_headers,
    _parse_built_from_notes,
    _version_key,
)


def _enc_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _field(num: int, wire: int, payload: bytes) -> bytes:
    return _enc_varint((num << 3) | wire) + payload


def _bytes_field(num: int, raw: bytes) -> bytes:
    return _field(num, 2, _enc_varint(len(raw)) + raw)


class PbTests(unittest.TestCase):
    def test_varint_roundtrip(self):
        for n in (0, 1, 127, 128, 300, 2**32 - 1):
            v, i = pb._read_varint(_enc_varint(n), 0)
            self.assertEqual((v, i), (n, len(_enc_varint(n))))

    def test_decode_mixed_fields(self):
        data = _field(3, 0, _enc_varint(42)) + _bytes_field(5, b"hi")
        fields = pb.decode_fields(data)
        self.assertEqual(pb.first_int(fields, 3), 42)
        self.assertEqual(pb.first_string(fields, 5), "hi")
        self.assertIsNone(pb.first_int(fields, 9))
        self.assertEqual(pb.first_string(fields, 9), "")

    def test_navigate_and_walk(self):
        inner = _bytes_field(4, b"tok")
        mid = _bytes_field(1, inner)
        outer = _bytes_field(1, mid)
        self.assertEqual(pb.first_string(pb.navigate(outer, 1, 1), 4), "tok")
        self.assertEqual(pb.navigate(outer, 1, 2), [])
        found = pb.walk_find(outer, lambda f: "yes" if pb.first_string(f, 4) == "tok" else None)
        self.assertEqual(found, ["yes"])
        # depth cap terminates hostile nesting (depths 0..12, not 30)
        deep = b"x"
        for _ in range(30):
            deep = _bytes_field(1, deep)
        self.assertEqual(len(pb.walk_find(deep, lambda f: "m")), 13)

    def test_truncated_input_does_not_raise(self):
        self.assertEqual(pb.decode_fields(b"\xff\xff"), [])


class VersionKeyTests(unittest.TestCase):
    def test_ordering(self):
        self.assertLess(_version_key("21.04.223"), _version_key("21.07.247"))
        self.assertLess(_version_key("1.0"), _version_key("1.0.1"))
        self.assertLess(_version_key("477.14"), _version_key("479.1"))

    def test_build_suffix_ignored_for_order(self):
        self.assertEqual(
            _version_key("32.30.0(1575420)")[:3], _version_key("32.30.0")[:3]
        )


class MorpheOutputTests(unittest.TestCase):
    SAMPLE = (
        "INFO: Package name: com.google.android.youtube\n"
        "INFO: Most common compatible versions:\n"
        "  21.07.247 [versionCodes: 1561056417, 1561056418] (34 patches)\n"
        "  21.04.223 [versionCodes: 1561052632] (33 patches)\n"
        "INFO: Package name: com.other.app\n"
        "INFO: Most common compatible versions:\n"
        "  2.2 build 016 (1 patch)\n"
    )

    def test_block_and_version_res(self):
        blocks = list(BLOCK_RE.finditer(self.SAMPLE))
        self.assertEqual(len(blocks), 2)
        vers = [m.group("ver") for m in VERSION_LINE_RE.finditer(blocks[0].group("versions"))]
        self.assertEqual(vers, ["21.07.247", "21.04.223"])
        self.assertEqual(
            [m.group("ver") for m in VERSION_LINE_RE.finditer(blocks[1].group("versions"))],
            ["2.2 build 016"],
        )

    def test_highest_picked_by_key(self):
        vers = ["21.04.223", "21.07.247"]
        self.assertEqual(max(vers, key=_version_key), "21.07.247")


class ReleaseNotesTests(unittest.TestCase):
    def test_parse_built(self):
        notes = "## Upstream updates\n- x\n\n## Built\n- a.apk\n- b.apk\n\nFull release contains 5 APKs"
        self.assertEqual(_parse_built_from_notes(notes), {"a.apk", "b.apk"})

    def test_empty_and_missing(self):
        self.assertEqual(_parse_built_from_notes(""), set())
        self.assertEqual(_parse_built_from_notes("## Other\n- a.apk\n"), set())


class GhHeadersTests(unittest.TestCase):
    def test_with_and_without_token(self):
        old = os.environ.get("GITHUB_TOKEN")
        try:
            os.environ["GITHUB_TOKEN"] = "abc"
            self.assertEqual(_gh_headers()["Authorization"], "Bearer abc")
            del os.environ["GITHUB_TOKEN"]
            self.assertNotIn("Authorization", _gh_headers())
        finally:
            if old is not None:
                os.environ["GITHUB_TOKEN"] = old
            else:
                os.environ.pop("GITHUB_TOKEN", None)


class IconHelperTests(unittest.TestCase):
    def test_hex_colors(self):
        from morpheupdater.fdroid import _parse_hex_color

        self.assertEqual(_parse_hex_color("#fff"), (255, 255, 255, 255))
        self.assertEqual(_parse_hex_color("#0000"), (0, 0, 0, 0))
        self.assertEqual(_parse_hex_color("#112233"), (17, 34, 51, 255))
        self.assertEqual(_parse_hex_color("#80112233"), (17, 34, 51, 128))
        self.assertIsNone(_parse_hex_color("red"))
        self.assertIsNone(_parse_hex_color("#12"))

    def test_path_tokenize_and_flatten(self):
        from morpheupdater.fdroid import _flatten_subpaths, _parse_path_data

        cmds = _parse_path_data("M0,0 L10,0 L10,10 L0,10 Z")
        kinds = [c for c, _ in cmds]
        self.assertEqual(kinds, ["M", "L", "L", "L", "Z"])
        subs = _flatten_subpaths(cmds)
        self.assertEqual(len(subs), 1)
        xs = [p[0] for p in subs[0]]
        self.assertAlmostEqual(min(xs), 0.0)
        self.assertAlmostEqual(max(xs), 10.0)

    def test_stray_number_before_command_ignored(self):
        from morpheupdater.fdroid import _parse_path_data

        self.assertEqual(_parse_path_data("42 M0,0 L1,1"), [("M", [0.0, 0.0]), ("L", [1.0, 1.0])])

    def test_arc_degenerate(self):
        from morpheupdater.fdroid import _arc_to_beziers

        self.assertEqual(_arc_to_beziers(0, 0, 0, 5, 0, 0, 1, 3, 4), [])

    def test_matrices(self):
        from morpheupdater.fdroid import _group_matrix, _mat_mul, _mat_pt

        ident = (1, 0, 0, 0, 1, 0, 0, 0, 1)
        self.assertEqual(_mat_mul(ident, ident), ident)
        self.assertEqual(_mat_pt(ident, 3.0, 4.0), (3.0, 4.0))
        m = _group_matrix({"translateX": 5.0, "translateY": 0.0, "scaleX": 1.0,
                           "scaleY": 1.0, "rotation": 0.0, "pivotX": 0.0, "pivotY": 0.0})
        self.assertEqual(_mat_pt(m, 1.0, 2.0), (6.0, 2.0))

    def test_fill_mask_square(self):
        from morpheupdater.fdroid import _fill_mask_device

        mask = _fill_mask_device([[(2.0, 2.0), (8.0, 2.0), (8.0, 8.0), (2.0, 8.0), (2.0, 2.0)]], 12)
        px = mask.load()
        self.assertEqual(px[5, 5], 255)
        self.assertEqual(px[0, 0], 0)

    def test_num_attr_encodings(self):
        from morpheupdater.fdroid import _num_attr

        self.assertEqual(_num_attr(0x03, 0, "18dp", 0.0), 18.0)
        self.assertAlmostEqual(_num_attr(0x03, 0, "25%", 0.0), 0.25)
        self.assertEqual(_num_attr(0x10, 7, None, 0.0), 7.0)
        import struct as _st

        bits = _st.unpack("<I", _st.pack("<f", 1.5))[0]
        self.assertAlmostEqual(_num_attr(0x04, bits, None, 0.0), 1.5)
        self.assertEqual(_num_attr(0x02, 0, None, 9.0), 9.0)

    def test_xmltree_raw_suffix(self):
        from morpheupdater.fdroid import _parse_xmltree

        out = (
            "E: vector (0x0)\n"
            '  A: viewportWidth="24.0"\n'
            '  A: pathData="M1,2 L3,4" (Raw: "M1,2 L3,4")\n'
            "  E: path (0x0)\n"
        )
        root = _parse_xmltree(out)
        self.assertIsNotNone(root)
        self.assertEqual(root[1]["pathData"], ("str", "M1,2 L3,4"))

    def test_is_blank_png(self):
        import tempfile
        from pathlib import Path

        from morpheupdater.fdroid import _is_blank_png

        with tempfile.TemporaryDirectory() as td:
            blank = Path(td) / "blank.png"
            solid = Path(td) / "solid.png"
            from PIL import Image

            Image.new("RGBA", (16, 16), (0, 0, 0, 0)).save(blank)
            Image.new("RGBA", (16, 16), (10, 20, 30, 255)).save(solid)
            self.assertTrue(_is_blank_png(blank))
            self.assertFalse(_is_blank_png(solid))
            self.assertTrue(_is_blank_png(Path(td) / "missing.png"))

    def test_gradient_fast_path(self):
        from morpheupdater.fdroid import _gradient_colors

        im = _gradient_colors([(255, 0, 0, 255), (0, 0, 255, 255)], 64)
        self.assertEqual(im.size, (64, 64))
        top = im.getpixel((32, 0))
        bot = im.getpixel((32, 63))
        self.assertGreater(top[0], 200)
        self.assertGreater(bot[2], 200)


class SettingsTests(unittest.TestCase):
    def test_short_names(self):
        self.assertEqual(short("com.google.android.youtube"), "youtube")
        # colliding generic tails keep the parent segment
        self.assertEqual(short("com.facebook.katana"), "katana")
        self.assertEqual(short("jp.pxv.android"), "pxv.android")
        self.assertEqual(short("videoeditor.videorecorder.screenrecorder"), "screenrecorder")

    def test_validate_apps_collision(self):
        cfg = {"apps": [{"package": "a.b.app"}, {"package": "c.b.app"}]}
        with self.assertRaises(SystemExit):
            validate_apps(cfg)
        validate_apps({"apps": [{"package": "a.b.youtube"}, {"package": "c.d.music"}]})

    def test_deep_merge(self):
        base = {"a": 1, "n": {"x": 1, "y": 2}}
        self.assertEqual(_deep_merge(base, {"n": {"y": 3}, "b": 2}),
                         {"a": 1, "n": {"x": 1, "y": 3}, "b": 2})


class PlayTests(unittest.TestCase):
    def test_guess_bounds_and_exact_base(self):
        guesses = play.guess_version_codes("25.3.0")
        self.assertTrue(guesses)
        self.assertTrue(all(0 < g < 2_147_483_647 for g in guesses))
        self.assertIn(25 * 100000 + 3 * 1000 + 0, guesses)
        self.assertEqual(len(set(guesses)), len(guesses))  # no dupes

    def test_version_re(self):
        self.assertTrue(play._VERSION_RE.match("21.07.247"))
        self.assertTrue(play._VERSION_RE.match("4.10.10-googleplay"))
        self.assertFalse(play._VERSION_RE.match("any"))

    def test_parse_version_codes_synthetic(self):
        payload = _bytes_field(5, b"1561056418") + _bytes_field(6, "21.07.247".encode())
        inner = _bytes_field(7, payload)
        raw = _bytes_field(1, inner)
        codes = play.parse_version_codes(raw)
        self.assertEqual(codes, {"21.07.247": 1561056418})

    def test_brute_force_budget(self):
        self.assertLessEqual(play.MAX_BRUTE_FORCE_ATTEMPTS, 100)


class PagesTests(unittest.TestCase):
    def test_compat_allows(self):
        self.assertTrue(_compat_allows({}, "P", "pkg", "orig"))
        self.assertTrue(_compat_allows({"P": None}, "P", "pkg", "orig"))
        self.assertTrue(_compat_allows({"P": set()}, "P", "pkg", "orig"))
        self.assertTrue(_compat_allows({"P": {"pkg"}}, "P", "pkg", "orig"))
        self.assertTrue(_compat_allows({"P": {"orig"}}, "P", "pkg", "orig"))
        self.assertFalse(_compat_allows({"P": {"other"}}, "P", "pkg", "orig"))


class DaemonHelperTests(unittest.TestCase):
    def test_enabled_archs(self):
        self.assertEqual(_enabled_archs(None), ["arm64"])
        self.assertEqual(_enabled_archs(["a", "b"]), ["a", "b"])
        self.assertEqual(_enabled_archs({"arm64": True, "x86": False}), ["arm64"])
        self.assertEqual(_enabled_archs("weird"), ["arm64"])

    def test_combo_id(self):
        self.assertEqual(combo_id(["morphe"]), "morphe")
        self.assertEqual(combo_id(["a", "b"]), "a+b")

    def test_repo_from_url(self):
        self.assertEqual(_repo_from_url("https://github.com/MorpheApp/morphe-patches"),
                         "MorpheApp/morphe-patches")
        self.assertIsNone(_repo_from_url("https://example.com/x"))

    def test_mpp_candidate(self):
        from pathlib import Path

        self.assertTrue(_is_mpp_candidate(Path("v1.0__patches-1.0.mpp")))
        self.assertFalse(_is_mpp_candidate(Path("x.mpp.part")))
        self.assertFalse(_is_mpp_candidate(Path("patches-sources.mpp")))

    def test_state_json_roundtrip(self):
        from morpheupdater.settings import load_state, save_state

        state = load_state()
        self.assertIn("builds", state)
        data = json.dumps(state)
        self.assertTrue(data.startswith("{"))


if __name__ == "__main__":
    unittest.main()
