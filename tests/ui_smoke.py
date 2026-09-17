"""Real-browser smoke test for the local Port Atlas console."""

from __future__ import annotations

import json
from pathlib import Path

from playwright.sync_api import expect, sync_playwright


BASE_URL = "http://127.0.0.1:8787/"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
ARTIFACTS = Path(__file__).with_name("artifacts")
PROJECTS_CONFIG = Path(__file__).parents[1] / "config" / "projects.json"


def main() -> None:
    ARTIFACTS.mkdir(exist_ok=True)
    expected_project_count = len(json.loads(PROJECTS_CONFIG.read_text(encoding="utf-8"))["projects"])
    results: dict[str, object] = {}
    severe_errors: list[str] = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, executable_path=CHROME)
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        page.on("console", lambda message: severe_errors.append(message.text) if message.type == "error" else None)
        page.goto(BASE_URL, wait_until="domcontentloaded")
        page.locator("#connectionText").get_by_text("本机服务正常", exact=True).wait_for(timeout=30000)

        rows = page.locator("#portsBody tr.port-row")
        results["initial_rows"] = rows.count()
        results["metrics"] = {
            key: page.locator(f"#{element_id}").inner_text()
            for key, element_id in {
                "tcp": "tcpMetric",
                "udp": "udpMetric",
                "unique": "uniqueMetric",
                "processes": "processMetric",
            }.items()
        }
        assert rows.count(), "Port table did not render any rows"
        page.screenshot(path=ARTIFACTS / "ports.png", full_page=True)

        page.locator('[data-protocol="running"]').click()
        running_texts = rows.all_inner_texts()
        assert running_texts and all("可以使用" in text for text in running_texts)
        results["running_rows"] = len(running_texts)

        page.locator("#portSearch").fill("8787")
        page.locator("#portsBody").get_by_text("8787", exact=True).wait_for()
        results["search_8787"] = page.locator("#portsBody").inner_text().splitlines()[:8]

        page.locator("#portsBody .detail-button").click()
        page.locator("#detailDialog").wait_for(state="visible")
        results["detail_title"] = page.locator("#detailTitle").inner_text()
        assert "8787" in str(results["detail_title"])
        page.locator("#closeDialog").click()

        page.locator('[data-view="projects"]').click()
        page.locator("#projectsView").wait_for(state="visible")
        page.wait_for_timeout(400)
        project_text = page.locator("#projectGrid").inner_text()
        assert "个人技能库" in project_text
        assert "HeyGem 数字人" in project_text
        assert "Qwen 本地模型" in project_text
        assert "CLI Proxy API" in project_text
        assert "AI 短视频生成" in project_text
        assert "Auria AI 产品作品集" in project_text
        assert "TalkCraft 动效工作台" in project_text
        project_cards = page.locator("#projectGrid .project-card")
        assert project_cards.count() == expected_project_count, (
            f"Expected {expected_project_count} registered projects, got {project_cards.count()}"
        )
        results["projects"] = project_text.splitlines()[:12]
        page.screenshot(path=ARTIFACTS / "projects.png", full_page=True)

        page.locator('[data-view="activity"]').click()
        page.locator("#activityView").wait_for(state="visible")
        expect(page.locator("#activityLog")).not_to_have_text("等待读取…")
        results["activity"] = page.locator("#activityLog").inner_text()[:500]

        results["severe_console_errors"] = severe_errors
        assert not severe_errors, f"Browser console errors: {severe_errors}"
        results["ok"] = True
        browser.close()

    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
