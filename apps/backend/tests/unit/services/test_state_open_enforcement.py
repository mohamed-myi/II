import inspect


def test_feed_personalized_enforces_open_state():
    from src.services import feed_service
    src = inspect.getsource(feed_service._get_personalized_feed)
    assert "i.state = 'open'" in src


def test_feed_trending_enforces_open_state():
    from src.services import feed_service
    src = inspect.getsource(feed_service._get_trending_feed)
    assert "i.state = 'open'" in src


def test_preview_enforces_open_state():
    from src.services import recommendation_preview_service as preview

    src_vector = inspect.getsource(preview._query_by_vector_similarity)
    src_trending = inspect.getsource(preview._query_trending_issues)

    assert "i.state = 'open'" in src_vector
    assert "i.state = 'open'" in src_trending


