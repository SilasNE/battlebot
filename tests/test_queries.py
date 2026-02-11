import app


def setup_module():
    app.init_db()


def test_vulnerable_query_is_injectable():
    rows, _ = app.vulnerable_search("' OR '1'='1")
    assert len(rows) >= 3


def test_safe_query_blocks_injection():
    rows, _ = app.safe_search("' OR '1'='1")
    assert rows == []
