"""Real Chromium E2E, no external models. Missing browser/dependency fails this lane."""

import asyncio
from dataclasses import replace
import json
import threading

import pytest
from playwright.sync_api import sync_playwright, expect

from blastcontain_drill.contracts import PluginManifest, SourceRef
from blastcontain_drill.suites.catalog import SourceSnapshot
from blastcontain_drill.suites.schema import ModelSettings
from blastcontain_drill.workbench.research import Research
from blastcontain_drill.workbench.server import WorkbenchServer
from blastcontain_drill.workbench.service import Runs, Workspace
from blastcontain_scout.arxiv import Paper
from blastcontain_scout.tracker import Tracker

HOSTILE = '<img src=x onerror="window.pwned=true">'


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        yield browser
        browser.close()


@pytest.fixture
def app(tmp_path, browser):
    workspace = Workspace(tmp_path / "workspace")
    started = threading.Event()

    async def blocking(*args, **kwargs):
        started.set()
        await asyncio.Event().wait()

    runs = Runs(workspace, transport=blocking)
    database = tmp_path / "scout.sqlite3"
    with Tracker(database) as tracker:
        tracker.ingest(
            [Paper("2601.12345", HOSTILE, "Controlled metadata", "2026-01-01", "2026-01-01")]
        )
    server = WorkbenchServer(workspace, runs, Research(database))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    context = browser.new_context(viewport={"width": 1360, "height": 1000})
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto(server.launch_url)
    expect(page.locator("#suite-id")).to_have_value("workbench-suite")
    yield page, workspace, runs, started, database
    context.close()
    server.shutdown()
    thread.join(5)
    server.server_close()
    runs.close()
    workspace.close()
    assert not errors


def panel(page, name):
    page.locator(f'[data-panel="{name}"]').click()


def accept(page):
    panel(page, "review")
    page.locator("#review-subject").select_option("suite")
    page.get_by_label("Reviewer", exact=True).fill("browser-reviewer")
    page.get_by_label("Reason", exact=True).fill("Reviewed controlled fixture")
    page.get_by_role("button", name="Accept exact scope").click()
    expect(page.locator("#notice")).to_contain_text("Recorded accepted")


def save_json(page, suite):
    panel(page, "compose")
    page.get_by_text("Advanced suite JSON", exact=True).click()
    page.get_by_label("Complete suite document").fill(json.dumps(suite))
    page.get_by_role("button", name="Save & preflight").click()
    expect(page.locator("#dirty-status")).to_have_text("Saved inputs")


@pytest.mark.parametrize("kind", ["agent", "mcp"])
def test_compose_accept_run_verify_and_mobile(app, tmp_path, kind):
    page, workspace, _, _, _ = app
    suite = workspace.snapshot()["suite"]
    suite["target"]["kind"] = kind
    suite["selections"] = [{"id": "mcp", "source": "mcp-poisoning", "scenarios": ["*"]}]
    save_json(page, suite)
    assert page.url.endswith("/")  # Bootstrap is removed from history.
    assert not page.context.cookies()  # No port-insensitive ambient auth cookie.
    accept(page)
    panel(page, "runs")
    page.get_by_role("button", name="Create accepted lock").click()
    expect(page.get_by_role("button", name="Start run")).to_be_enabled()
    page.get_by_role("button", name="Start run").click()
    expect(page.get_by_text("Finished", exact=True)).to_be_visible(timeout=20000)
    page.get_by_role("button", name="Verify evidence").click()
    expect(page.locator("#verification-status")).to_contain_text("Replay complete")
    expect(page.locator("#verification-status")).to_contain_text("Security checks passed")
    expect(page.locator("#verification-status")).to_contain_text("No attested pass")
    page.screenshot(path=str(tmp_path / (kind + "-desktop.png")), full_page=True)
    page.set_viewport_size({"width": 390, "height": 844})
    page.screenshot(path=str(tmp_path / (kind + "-mobile.png")), full_page=True)
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    page.reload()
    expect(page.locator("#suite-id")).to_have_value("workbench-suite")
    page.keyboard.press("Tab")
    expect(page.get_by_role("link", name="Skip to workspace")).to_be_focused()


def test_candidate_review_import_scope_change_and_hostile_metadata(app):
    page, workspace, _, _, database = app
    panel(page, "research")
    expect(page.get_by_role("heading", name=HOSTILE)).to_be_visible()
    assert page.evaluate("window.pwned === undefined")
    page.get_by_label("Research status for 2601.12345").select_option("selected")
    page.get_by_label("Research reviewer for 2601.12345").fill("research-reviewer")
    page.get_by_label("Research note for 2601.12345").fill("Candidate for controlled reproduction")
    page.get_by_role("button", name="Save research review").click()
    expect(page.locator("#notice")).to_contain_text("Research review saved")
    with Tracker(database, readonly=True) as tracker:
        assert tracker.snapshot()["papers"][0]["review_status"] == "selected"
    panel(page, "review")
    scenario = workspace.inputs().catalog.sources[0].scenarios[0]
    source = SourceSnapshot(
        "paper-2601.12345",
        "v1",
        "sha256:" + "a" * 64,
        (replace(scenario, source=SourceRef("paper-2601.12345", "v1")),),
    )
    page.get_by_label("Artifact kind").select_option("source")
    page.get_by_label("Artifact JSON", exact=True).fill(json.dumps(source.to_dict()))
    page.get_by_role("button", name="Import metadata").click()
    expect(page.locator("#artifact-cards")).to_contain_text("paper-2601.12345")
    page.get_by_label("Review subject").select_option(label="content · paper-2601.12345")
    page.get_by_label("Reviewer", exact=True).fill("browser-reviewer")
    page.get_by_label("Reason", exact=True).fill("Controlled source, not a paper reproduction")
    page.get_by_role("button", name="Accept exact scope").click()
    expect(page.locator("#artifact-cards")).to_contain_text("Accepted current bytes")
    plugin = PluginManifest(
        "fixture-plugin",
        "1",
        "sha256:" + "b" * 64,
        ("attack_strategy",),
        ("prompt.single",),
        "Apache-2.0",
        access_requests=("broker.attacker",),
        notices=(HOSTILE,),
    )
    page.get_by_label("Artifact kind").select_option("plugin")
    page.get_by_label("Artifact JSON", exact=True).fill(json.dumps(plugin.to_dict()))
    page.get_by_role("button", name="Import metadata").click()
    page.get_by_label("Review subject").select_option(label="plugin · fixture-plugin")
    page.get_by_role("button", name="Accept exact scope").click()
    expect(page.locator("#notice")).to_contain_text("exactly match")
    page.get_by_label("broker.attacker", exact=True).check()
    page.get_by_role("button", name="Accept exact scope").click()
    expect(page.locator("#notice")).to_contain_text("Recorded accepted")
    changed = replace(plugin, version="2", access_requests=("broker.attacker", "broker.evaluator"))
    page.get_by_label("Artifact JSON", exact=True).fill(json.dumps(changed.to_dict()))
    page.get_by_role("button", name="Import metadata").click()
    expect(page.locator("#artifact-cards")).to_contain_text("Review required")
    assert page.evaluate("window.pwned === undefined")
    suite = workspace.snapshot()["suite"]
    suite["selections"] = [
        {"id": "paper", "source": source.id, "scenarios": ["*"], "strategy": plugin.id}
    ]
    save_json(page, suite)
    expect(page.locator("#plan-status")).to_have_text("Blocked")
    expect(page.locator("#diagnostics")).to_contain_text("plugin")
    page.reload()
    panel(page, "review")
    expect(page.locator("#decision-history")).to_contain_text("fixture-plugin: accepted")


def test_stale_draft_cannot_replace_newer_work_and_cancel_independent(app):
    page, workspace, runs, started, _ = app
    page.get_by_label("Suite ID", exact=True).fill("draft-old")
    state = workspace.snapshot()
    workspace.save_suite({**state["suite"], "id": "newer"}, state["revision"])
    page.get_by_role("button", name="Save & preflight").click()
    expect(page.locator("#notice")).to_contain_text("changed")
    expect(page.get_by_role("button", name="Save & preflight")).to_be_disabled()
    page.get_by_role("button", name="Reload latest").click()
    expect(page.get_by_label("Suite ID", exact=True)).to_have_value("newer")
    suite = workspace.snapshot()["suite"]
    suite["target"]["binding"] = "builtin.target.llm"
    suite["selections"] = [{"id": "mcp", "source": "mcp-poisoning", "scenarios": ["*"]}]
    suite["models"] = [
        ModelSettings("target", "http://127.0.0.1:1234/v1", "org/model:tag").to_dict()
    ]
    save_json(page, suite)
    accept(page)
    panel(page, "runs")
    page.get_by_role("button", name="Create accepted lock").click()
    expect(page.get_by_role("button", name="Start run")).to_be_enabled()
    page.get_by_role("button", name="Start run").click()
    assert started.wait(15)
    page.get_by_role("button", name="Stop run").click()
    expect(page.get_by_text("Finished", exact=True)).to_be_visible(timeout=20000)
    page.get_by_role("button", name="Verify evidence").click()
    expect(page.locator("#verification-status")).to_contain_text("No security pass")
    assert not runs.snapshot()["runs"][0]["reported_security_passed"]
