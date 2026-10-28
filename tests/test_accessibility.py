"""Accessibility regression tests for the home page UI.

These guard the accessibility fixes to the base and home templates, the
flash-message helpers, and the markdown sanitizer: landmark structure,
unique ids, labeled controls, list semantics, and preserved heading anchors.

The rendered-page tests exercise the unauthenticated home page. Markup that
only renders for authenticated or admin users (the navbar dropdowns, the
search form, the Recent Activity table) is checked at the template-source
level instead, since those regressions are textual and unambiguous.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from lxml import html as lxml_html

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = REPO_ROOT / "libreforms_fastapi" / "app" / "templates"
STATIC_DIR = REPO_ROOT / "libreforms_fastapi" / "app" / "static"


@pytest.fixture(scope="module")
def client():
    from libreforms_fastapi.app import app
    return TestClient(app)


@pytest.fixture(scope="module")
def home_tree(client):
    response = client.get("/ui/home")
    assert response.status_code == 200
    return lxml_html.fromstring(response.text)


# Rendered-page checks (unauthenticated variant)

def test_home_page_declares_language(home_tree):
    html_el = home_tree.getroottree().getroot()
    assert html_el.get("lang"), "the <html> element should declare a lang"


def test_home_page_has_skip_link_and_main_landmark(home_tree):
    assert home_tree.xpath('//a[@href="#main-content"]'), \
        "expected a skip-to-main-content link"
    assert home_tree.xpath('//main[@id="main-content"]'), \
        "expected <main id='main-content'> as the skip link target"


def test_home_page_has_no_duplicate_ids(home_tree):
    ids = home_tree.xpath("//@id")
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    assert not duplicates, f"duplicate id attributes rendered: {duplicates}"


def test_home_page_lists_contain_only_list_items(home_tree):
    for list_el in home_tree.xpath("//ul | //ol"):
        for child in list_el:
            if not isinstance(child.tag, str):
                continue  # skip comments
            assert child.tag == "li", (
                f"<{list_el.tag}> has a direct <{child.tag}> child; "
                "only <li> is valid list markup"
            )


def test_home_page_buttons_have_accessible_names(home_tree):
    for button in home_tree.xpath("//button"):
        name = (
            (button.text_content() or "").strip()
            or button.get("aria-label")
            or button.get("aria-labelledby")
        )
        assert name, "found a <button> with no accessible name"


# Template-source checks (markup that only renders when authenticated)

def test_base_template_dropdown_ids_are_unique():
    src = (TEMPLATES_DIR / "base.html.jinja").read_text()
    # Both navbar dropdown buttons once shared id="AdminMenu", so the Admin
    # menu was announced as "Manage Submissions" via aria-labelledby
    assert src.count('id="AdminMenu"') == 1
    assert src.count('id="manageSubmissionsMenu"') == 1


def test_base_template_navbar_children_are_list_items():
    src = (TEMPLATES_DIR / "base.html.jinja").read_text()
    assert '<div class="nav-item dropdown">' not in src, \
        "navbar dropdowns must be <li> elements, not <div>, inside <ul>"


def test_base_template_search_input_is_labeled():
    src = (TEMPLATES_DIR / "base.html.jinja").read_text()
    assert '<label for="searchTerm"' in src, \
        "the navbar search input needs a label, a placeholder is not one"


def test_home_template_table_semantics():
    src = (TEMPLATES_DIR / "home.html.jinja").read_text()
    assert src.count('<th scope="col">') == 6, \
        "every Recent Activity column header needs scope='col'"
    assert "<caption" in src, "the Recent Activity table needs a caption"
    assert 'role="status"' in src, \
        "loading/empty states need a live region to be announced"


def test_home_template_profile_badges_not_disabled_with_pointer_events():
    src = (TEMPLATES_DIR / "home.html.jinja").read_text()
    # pointer-events:none only blocks the mouse; the link stayed focusable
    # and operable from the keyboard
    assert "pointer-events: none" not in src
    assert "profileLinksEnabled" in src


def test_home_template_sorts_on_time_datetime_attribute():
    src = (TEMPLATES_DIR / "home.html.jinja").read_text()
    # The timestamp cells render <time datetime="..."> and the DataTables
    # sort renderer must read the same attribute, or date sorting breaks
    assert "<time datetime=" in src
    assert "attr('datetime')" in src
    assert "attr('title')" not in src


def test_flash_message_dismiss_button_is_labeled():
    src = (STATIC_DIR / "js" / "custom.js").read_text()
    assert '"aria-label": "Dismiss this message"' in src


# Backend-generated HTML (markdown rendering pipeline)

def test_rendered_markdown_keeps_heading_anchors():
    from libreforms_fastapi.utils.docs import render_markdown_content
    out = render_markdown_content("# Welcome\n\n[TOC]\n\n## Section one\n")
    assert 'id="welcome"' in out, \
        "the sanitizer stripped the heading ids the toc extension generates"
    assert 'href="#welcome"' in out
    assert 'id="section-one"' in out


def test_rendered_markdown_allows_h6():
    from libreforms_fastapi.utils.docs import render_markdown_content
    out = render_markdown_content("###### Small heading\n")
    assert "<h6" in out
