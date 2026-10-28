import unittest

from vulnscan.inventory import normalize_installed_version


class InventoryVersionTests(unittest.TestCase):
    def test_python_registry_build_id_uses_release_in_display_name(self):
        self.assertEqual(normalize_installed_version("Python 3.13.15 (64-bit)", "3.13.15150.0"), "3.13.15")

    def test_python_component_uses_release_in_display_name(self):
        self.assertEqual(normalize_installed_version("Python 3.13.15 Core Interpreter (64-bit)", "3.13.15150.0"), "3.13.15")

    def test_other_products_keep_registry_version(self):
        self.assertEqual(normalize_installed_version("Google Chrome", "156.0.4314.50"), "156.0.4314.50")

    def test_dotnet_runtime_uses_release_in_display_name(self):
        self.assertEqual(normalize_installed_version("Microsoft .NET Runtime - 8.0.22 (x64)", "64.88.42551"), "8.0.22")

    def test_dotnet_desktop_runtime_uses_release_in_display_name(self):
        self.assertEqual(normalize_installed_version("Microsoft Windows Desktop Runtime - 10.0.11 (x64)", "80.44.56884"), "10.0.11")


if __name__ == "__main__":
    unittest.main()
