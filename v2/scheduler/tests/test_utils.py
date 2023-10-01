from utils import get_chunks


def test_chunks():
    assert get_chunks([], 2) == []
    assert get_chunks(["a"], 2) == [["a"]]
    assert get_chunks(["a", "b"], 2) == [["a"], ["b"]]
    assert get_chunks(["a", "b", "c"], 2) == [["a", "b"], ["c"]]
    assert get_chunks(["a", "b", "c", "d", "e"], 3) == [["a", "b"], ["c", "d"], ["e"]]

