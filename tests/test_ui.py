"""Browser regressions for reference links, filtering, and responsive accordions."""

import functools
import http.server
import os
from pathlib import Path
import threading
import unittest

from playwright.sync_api import sync_playwright


ROOT = Path(__file__).resolve().parents[1]


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


class CatalogUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        handler = functools.partial(QuietHandler, directory=str(ROOT))
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}/"
        cls.playwright = sync_playwright().start()
        options = {"headless": True}
        if executable := os.environ.get("CHROMIUM_EXECUTABLE"):
            options["executable_path"] = executable
        cls.browser = cls.playwright.chromium.launch(**options)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.context = self.browser.new_context(viewport={"width": 1280, "height": 900})
        self.page = self.context.new_page()
        # Fonts are optional; these tests must not depend on external services.
        self.page.route("https://**/*", lambda route: route.abort())
        self.errors = []
        self.page.on("pageerror", lambda error: self.errors.append(str(error)))

    def tearDown(self):
        self.context.close()
        self.assertEqual(self.errors, [])

    def open_first_entry(self):
        self.page.goto(self.base_url)
        self.page.locator(".row").first.click()
        self.page.wait_for_timeout(450)

    def test_reference_urls_cannot_inject_html_or_script_schemes(self):
        data = (ROOT / "data.js").read_text(encoding="utf-8")
        data += '''
ENTRIES[0].refs = [
  {title: "quoted URL", url: 'https://example.org/\"><img id="injected" src="bad" onerror="window.injected=true"><a href="https://example.org/'},
  {title: "script URL", url: "javascript:window.injected=true"},
  {title: "valid URL", url: "https://example.org/?a=1&b=2"}
];
'''
        self.page.route("**/data.js*", lambda route: route.fulfill(body=data, content_type="text/javascript"))
        self.open_first_entry()
        self.assertEqual(self.page.locator("#injected").count(), 0)
        self.assertFalse(self.page.evaluate("window.injected === true"))
        links = self.page.locator(".entry.active .reflist a")
        self.assertEqual(links.count(), 3)
        self.assertEqual(links.nth(1).get_attribute("href"), "#")
        self.assertEqual(links.nth(2).get_attribute("href"), "https://example.org/?a=1&b=2")

    def test_filtering_out_selection_clears_detail_and_permalink(self):
        self.open_first_entry()
        selected_category = self.page.locator("#detail-inner .d-kicker").text_content().strip()
        categories = self.page.locator("#f-category option").evaluate_all("els => els.map(e => e.value)")
        category = next(c for c in categories if c and c != selected_category)
        self.page.select_option("#f-category", category)
        self.assertEqual(self.page.locator(".entry.active").count(), 0)
        self.assertEqual(self.page.locator("#detail-inner .d-empty").count(), 1)
        self.assertEqual(self.page.evaluate("location.hash"), "")
        self.page.reload()
        self.assertEqual(self.page.locator("#detail-inner .d-empty").count(), 1)
        self.assertEqual(self.page.locator(".entry.active").count(), 0)

    def assert_body_fits(self):
        self.page.wait_for_timeout(450)
        measurements = self.page.locator(".entry.active .body").evaluate(
            "el => ({height: el.clientHeight, content: el.scrollHeight})"
        )
        self.assertLessEqual(measurements["content"] - measurements["height"], 1)

    def test_expanded_content_follows_viewport_and_content_changes(self):
        self.open_first_entry()
        self.assert_body_fits()
        self.page.set_viewport_size({"width": 600, "height": 900})
        self.assert_body_fits()
        self.page.locator(".entry.active .d-summary").evaluate("el => el.textContent += ' extra text '.repeat(600)")
        self.assert_body_fits()
        self.page.set_viewport_size({"width": 1280, "height": 900})
        self.assert_body_fits()

    def test_deep_link_and_related_navigation_still_expand_entries(self):
        self.page.goto(self.base_url + "#entra-device-code")
        self.assertEqual(self.page.locator(".entry.active").get_attribute("data-id"), "entra-device-code")
        self.assert_body_fits()
        self.page.locator(".entry.active .related-link").first.click()
        self.assertEqual(self.page.locator(".entry.active").get_attribute("data-id"), "foci-pivot")
        self.assert_body_fits()

    def test_data_access_links_and_api_metadata(self):
        self.page.goto(self.base_url)
        api_link = self.page.locator('.data-link[href="api/entries.json"]')
        self.assertEqual(api_link.count(), 1)
        self.assertNotEqual(api_link.get_attribute("download"), None)
        response = self.page.request.get(self.base_url + "api/entries.json")
        self.assertTrue(response.ok)
        payload = response.json()
        self.assertEqual(payload["version"], "0.6")
        self.assertEqual(payload["license"], "MIT")
        self.assertEqual(payload["stats"]["entries"], len(payload["entries"]))
        snippets = [snippet for entry in payload["entries"] for snippet in entry.get("detection_code", [])]
        self.assertTrue(snippets)
        self.assertTrue(all("status" in snippet for snippet in snippets))


if __name__ == "__main__":
    unittest.main()
