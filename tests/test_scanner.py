import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import scanner


class PortScannerTests(unittest.TestCase):
    def test_parses_ports_and_ranges(self):
        self.assertEqual(scanner.parse_ports("80,443,8000-8002"), [80, 443, 8000, 8001, 8002])

    def test_rejects_invalid_or_oversized_ranges(self):
        for value in ("0", "65536", "90-80", "22-3000", "abc"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                scanner.parse_ports(value)


if __name__ == "__main__":
    unittest.main()

