from src.services.feed_service import freshness_decay


def test_freshness_decay_is_1_for_non_positive_age():
    assert freshness_decay(age_days=0.0, half_life_days=7.0, floor=0.2) == 1.0
    assert freshness_decay(age_days=-1.0, half_life_days=7.0, floor=0.2) == 1.0


def test_freshness_decay_respects_floor():
    val = freshness_decay(age_days=365.0, half_life_days=7.0, floor=0.2)
    assert val >= 0.2


def test_freshness_decay_half_life_behavior():
    v0 = freshness_decay(age_days=0.0, half_life_days=7.0, floor=0.0)
    v7 = freshness_decay(age_days=7.0, half_life_days=7.0, floor=0.0)
    v14 = freshness_decay(age_days=14.0, half_life_days=7.0, floor=0.0)

    assert v0 == 1.0
    assert abs(v7 - 0.5) < 1e-6
    assert abs(v14 - 0.25) < 1e-6


