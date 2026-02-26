import os
from urllib.parse import quote_plus

from playwright.sync_api import sync_playwright


class ManualGoogleSession:
    """Visible browser session for manual CAPTCHA solving before parsing."""

    def __init__(self, profile_root: str):
        self.profile_dir = os.path.join(profile_root, "manual_google_profile")
        self.playwright = None
        self.context = None
        self.page = None

    def start_search(self, query: str) -> None:
        os.makedirs(self.profile_dir, exist_ok=True)

        if self.context is None:
            self.playwright = sync_playwright().start()
            self.context = self.playwright.chromium.launch_persistent_context(
                user_data_dir=self.profile_dir,
                headless=False,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-first-run",
                    "--no-default-browser-check",
                ],
                locale="ru-RU",
                viewport={"width": 1366, "height": 900},
            )

        if not self.context.pages:
            self.page = self.context.new_page()
        else:
            self.page = self.context.pages[0]

        search_url = f"https://www.google.com/search?q={quote_plus(query)}&hl=ru&num=100"
        self.page.goto(search_url, wait_until="domcontentloaded", timeout=45000)
        self.page.bring_to_front()

    def export_storage_state(self) -> str:
        if self.context is None:
            raise RuntimeError("Manual browser session is not started")

        state_path = os.path.join(self.profile_dir, "storage_state.json")
        self.context.storage_state(path=state_path)
        return state_path

    def is_active(self) -> bool:
        return self.context is not None

    def stop(self) -> None:
        if self.context is not None:
            try:
                self.context.close()
            except Exception:
                pass
            self.context = None
            self.page = None

        if self.playwright is not None:
            try:
                self.playwright.stop()
            except Exception:
                pass
            self.playwright = None
