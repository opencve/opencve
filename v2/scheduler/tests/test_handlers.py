import json
import logging

from includes.handlers import DiffHandler


logger = logging.getLogger(__name__)


def test_diff_handler_properties(tests_path, cvelistv5_repo):
    # Third update (Sun Jan 1 02:10:00 2023 +0000)
    #  cves/2023/5xxx/CVE-2023-5301.json |   6 +++
    #  cves/2023/5xxx/CVE-2023-5305.json | 126 ++++++++++++++++++++++++++++++++++++++++++++++
    #  2 files changed, 132 insertions(+)
    commit = next(cvelistv5_repo.iter_commits())

    # cves/2023/5xxx/CVE-2023-5301.json (new reference)
    diff = commit.parents[0].diff(commit)[0]
    handler = DiffHandler(logger, commit, diff)

    assert handler.is_new is False
    assert handler.path == "cves/2023/5xxx/CVE-2023-5301.json"

    # Left is old version of the CVE
    with open(tests_path / "data/cvelistV5/b/cves/2023/5xxx/CVE-2023-5301.json") as f:
        old_version = json.load(f)
    assert handler.left == old_version

    # Right is new version of the CVE
    with open(tests_path / "data/cvelistV5/c/cves/2023/5xxx/CVE-2023-5301.json") as f:
        new_version = json.load(f)
    assert handler.right == new_version


def test_diff_handler_handle():
    pass


def test_diff_handler_create_change():
    pass
