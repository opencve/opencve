import json
import logging
import pathlib
from unittest.mock import patch, mock_open, MagicMock

from email.mime.multipart import MIMEMultipart
import openai
import pytest
import pendulum

from utils import TestRepo
from includes.utils import (
    divide_list,
    group_changes_by_vendor,
    format_change_details,
    merge_project_subscriptions,
    list_changes_by_project,
    group_notifications_by_project,
    get_dates_from_context,
    list_commits,
    get_smtp_conf,
    get_smtp_message,
    should_execute,
    call_llm,
    read_cve_from_kb,
    build_scores_distribution,
    build_user_content_for_llm,
)


logger = logging.getLogger(__name__)


def test_divide_list():
    assert divide_list(["a", "b", "c", "d"], 5) == [["a"], ["b"], ["c"], ["d"]]
    assert divide_list(["a", "b", "c", "d"], 4) == [["a"], ["b"], ["c"], ["d"]]
    assert divide_list(["a", "b", "c", "d"], 3) == [["a", "b"], ["c"], ["d"]]
    assert divide_list(["a", "b", "c", "d"], 2) == [["a", "b"], ["c", "d"]]
    assert divide_list(["a", "b", "c", "d"], 1) == [["a", "b", "c", "d"]]


def test_group_changes_by_vendor():
    records = [
        ("change1", [], "", ["vendor1", "product1"], "", {}),
        ("change2", [], "", ["vendor2", "product2"], "", {}),
        ("change3", [], "", ["vendor3", "product3"], "", {}),
        ("change4", [], "", ["vendor1", "product2"], "", {}),
    ]

    assert group_changes_by_vendor(records) == {
        "vendor1": ["change1", "change4"],
        "vendor2": ["change2"],
        "vendor3": ["change3"],
        "product1": ["change1"],
        "product2": ["change2", "change4"],
        "product3": ["change3"],
    }


def test_format_change_details():
    records = [
        (
            "change1",
            ["type1"],
            "2024/CVE-2024-0001.json",
            ["vendor1"],
            "CVE-2024-0001",
            {"cvssV3_1": {}},
        ),
        (
            "change2",
            ["type2"],
            "2024/CVE-2024-0002.json",
            ["vendor2"],
            "CVE-2024-0002",
            {"cvssV4_0": {}},
        ),
    ]
    assert format_change_details(records) == {
        "change1": {
            "change_id": "change1",
            "change_types": ["type1"],
            "change_path": "2024/CVE-2024-0001.json",
            "cve_vendors": ["vendor1"],
            "cve_id": "CVE-2024-0001",
            "cve_metrics": {"cvssV3_1": {}},
        },
        "change2": {
            "change_id": "change2",
            "change_types": ["type2"],
            "change_path": "2024/CVE-2024-0002.json",
            "cve_vendors": ["vendor2"],
            "cve_id": "CVE-2024-0002",
            "cve_metrics": {"cvssV4_0": {}},
        },
    }


def test_merge_project_subscriptions():
    records = [
        ("project1", {"vendors": [], "products": ["product1"]}),
        ("project2", {"vendors": ["vendor1"], "products": []}),
        ("project3", {"vendors": ["vendor1"], "products": ["product1"]}),
        (
            "project4",
            {"vendors": ["vendor1", "vendor2"], "products": ["product1", "product2"]},
        ),
    ]
    assert merge_project_subscriptions(records) == {
        "project1": ["product1"],
        "project2": ["vendor1"],
        "project3": ["vendor1", "product1"],
        "project4": ["vendor1", "vendor2", "product1", "product2"],
    }


def test_list_changes_by_project():
    changes = {
        "vendor1": ["change1"],
        "vendor2": ["change1", "change2"],
        "vendor3": ["change3"],
    }
    subscriptions = {
        "project1": [],
        "project2": ["vendor1"],
        "project3": ["vendor2"],
        "project4": ["vendor1", "vendor2"],
        "project5": ["vendor1", "vendor2", "vendor3"],
    }
    assert sorted(list_changes_by_project(changes, subscriptions)) == sorted(
        {
            "project2": ["change1"],
            "project3": ["change1", "change2"],
            "project4": ["change1", "change2"],
            "project5": ["change1", "change2", "change3"],
        }
    )


def test_get_project_notifications():
    records = [
        (
            "project-id-1",
            "project-name-1",
            "organization-1",
            "notification-1",
            "webhook",
            {
                "types": ["created", "weaknesses", "cpes"],
                "extras": {"url": "https://localhost:5000", "headers": {"foo": "bar"}},
                "metrics": {"cvss31": "4"},
            },
        ),
        (
            "project-id-1",
            "project-name-1",
            "organization-1",
            "notification-2",
            "email",
            {
                "types": ["references"],
                "extras": {},
                "metrics": {"cvss31": "8"},
            },
        ),
        (
            "project-id-2",
            "project-name-2",
            "organization-2",
            "notification-3",
            "email",
            {
                "types": ["cpes"],
                "extras": {},
                "metrics": {"cvss31": "0"},
            },
        ),
    ]
    subscriptions = {"project-id-1": ["foo", "foo$PRODUCT$bar"]}
    assert group_notifications_by_project(records, subscriptions) == {
        "project-id-1": [
            {
                "project_id": "project-id-1",
                "project_name": "project-name-1",
                "project_subscriptions": [
                    "foo",
                    "foo$PRODUCT$bar",
                ],
                "organization_name": "organization-1",
                "notification_name": "notification-1",
                "notification_type": "webhook",
                "notification_conf": {
                    "types": ["created", "weaknesses", "cpes"],
                    "extras": {
                        "url": "https://localhost:5000",
                        "headers": {"foo": "bar"},
                    },
                    "metrics": {"cvss31": "4"},
                },
            },
            {
                "project_id": "project-id-1",
                "project_name": "project-name-1",
                "project_subscriptions": [
                    "foo",
                    "foo$PRODUCT$bar",
                ],
                "organization_name": "organization-1",
                "notification_name": "notification-2",
                "notification_type": "email",
                "notification_conf": {
                    "types": ["references"],
                    "extras": {},
                    "metrics": {"cvss31": "8"},
                },
            },
        ],
        "project-id-2": [
            {
                "project_id": "project-id-2",
                "project_name": "project-name-2",
                "project_subscriptions": [],
                "organization_name": "organization-2",
                "notification_name": "notification-3",
                "notification_type": "email",
                "notification_conf": {
                    "types": ["cpes"],
                    "extras": {},
                    "metrics": {"cvss31": "0"},
                },
            }
        ],
    }


def test_get_dates_from_context():
    context = {
        "data_interval_start": pendulum.parse("2024-01-01T10:00:00"),
        "data_interval_end": pendulum.parse("2024-01-01T11:00:00"),
    }
    assert get_dates_from_context(context) == (
        pendulum.parse("2024-01-01T10:00:00"),
        pendulum.parse("2024-01-01T10:59:59"),
    )


def test_list_commits(tests_path, tmp_path_factory):
    repo = TestRepo("example", tests_path, tmp_path_factory)
    commit_a = repo.commit(["a/"], hour=1, minute=00)
    commit_b = repo.commit(["b/"], hour=2, minute=00)
    commit_c = repo.commit(["c/"], hour=2, minute=30)

    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path):
        # No commit between 12:00 and 12:59:59
        assert (
            list_commits(
                logger,
                pendulum.datetime(2024, 1, 1, 12, tz="UTC"),
                pendulum.datetime(2024, 1, 1, 13, tz="UTC"),
            )
            == []
        )

        # One commit between 01:00 and 01:59:59
        assert list_commits(
            logger,
            pendulum.datetime(2024, 1, 1, 1, tz="UTC"),
            pendulum.datetime(2024, 1, 1, 2, tz="UTC"),
        ) == [commit_a]

        # Two commits between 02:00 and 02:59:59
        assert list_commits(
            logger,
            pendulum.datetime(2024, 1, 1, 2, tz="UTC"),
            pendulum.datetime(2024, 1, 1, 3, tz="UTC"),
        ) == [commit_b, commit_c]

        # Three commits between 10:00 and 02:59:59
        assert list_commits(
            logger,
            pendulum.datetime(2024, 1, 1, 1, tz="UTC"),
            pendulum.datetime(2024, 1, 1, 3, tz="UTC"),
        ) == [commit_a, commit_b, commit_c]


def test_get_smtp_conf(override_confs):
    override_confs(
        "opencve",
        {
            "notification_smtp_host": "smtp.example.com",
            "notification_smtp_mail_from": "john@example.com",
            "notification_smtp_port": "587",
            "notification_smtp_use_tls": "True",
            "notification_smtp_validate_certs": "True",
            "notification_smtp_timeout": "30",
            "notification_smtp_user": "user",
            "notification_smtp_password": "password",
            "notification_smtp_start_tls": "True",
        },
    )

    # All available settings
    assert get_smtp_conf() == {
        "hostname": "smtp.example.com",
        "port": 587,
        "use_tls": True,
        "validate_certs": True,
        "timeout": 30,
        "username": "user",
        "password": "password",
        "start_tls": True,
    }

    # Remove optional settings (user, password, start_tls)
    override_confs(
        "opencve",
        {
            "notification_smtp_host": "smtp.example.com",
            "notification_smtp_mail_from": "john@example.com",
            "notification_smtp_port": "587",
            "notification_smtp_use_tls": "True",
            "notification_smtp_validate_certs": "True",
            "notification_smtp_timeout": "30",
            "notification_smtp_user": "",
            "notification_smtp_password": "",
            "notification_smtp_start_tls": "",
        },
    )
    assert get_smtp_conf() == {
        "hostname": "smtp.example.com",
        "port": 587,
        "use_tls": True,
        "validate_certs": True,
        "timeout": 30,
    }


@pytest.mark.asyncio
async def test_get_smtp_message(override_conf):
    override_conf("opencve", "notification_smtp_mail_from", "from@example.com")
    message = await get_smtp_message(
        email_to="to@example.com",
        subject="Test Subject",
        template="email_test",
        context={"web_url": "https://app.opencve.io"},
    )
    assert isinstance(message, MIMEMultipart)
    assert "From: from@example.com" in message.as_string()
    assert "To: to@example.com" in message.as_string()
    assert "Subject: Test Subject" in message.as_string()


@patch("airflow.models.Variable.get")
def test_should_execute_function_with_different_values(mock_variable_get):
    """Test the should_execute function with different values"""
    # Test with "true"
    mock_variable_get.return_value = "true"
    assert should_execute("test_var") is True

    # Test with "false"
    mock_variable_get.return_value = "false"
    assert should_execute("test_var") is False

    # Test with other value
    mock_variable_get.return_value = "other"
    assert should_execute("test_var") is False


@patch("includes.utils.openai.OpenAI")
def test_call_llm_success(mock_openai_client):
    """Test successful LLM API call"""
    mock_client_instance = mock_openai_client.return_value
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "This is a test response from the LLM"
    mock_client_instance.chat.completions.create.return_value = mock_response

    result = call_llm(
        api_key="test-api-key",
        api_url="https://api.test.com",
        model="Mistral-7B-Instruct-v0.3",
        messages=[{"role": "user", "content": "Test message"}],
    )

    assert result == "This is a test response from the LLM"
    mock_openai_client.assert_called_once_with(
        api_key="test-api-key", base_url="https://api.test.com"
    )
    mock_client_instance.chat.completions.create.assert_called_once_with(
        model="Mistral-7B-Instruct-v0.3",
        messages=[{"role": "user", "content": "Test message"}],
    )


@patch("includes.utils.openai.OpenAI")
def test_call_llm_rate_limit_error(mock_openai_client):
    """Test LLM API call with rate limit error"""
    mock_client_instance = mock_openai_client.return_value
    mock_response = MagicMock()
    mock_response.status_code = 429
    mock_response.headers = {"x-request-id": "test-request-id"}
    mock_response.request = MagicMock()
    mock_client_instance.chat.completions.create.side_effect = openai.RateLimitError(
        "Rate limit exceeded", response=mock_response, body=None
    )

    result = call_llm(
        api_key="test-api-key",
        api_url="https://api.test.com",
        model="Mistral-7B-Instruct-v0.3",
        messages=[{"role": "user", "content": "Test message"}],
    )

    assert result is None
    mock_openai_client.assert_called_once_with(
        api_key="test-api-key", base_url="https://api.test.com"
    )


@patch("includes.utils.openai.OpenAI")
def test_call_llm_api_error(mock_openai_client):
    """Test LLM API call with API error"""
    mock_client_instance = mock_openai_client.return_value
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.headers = {"x-request-id": "test-request-id"}
    mock_response.request = MagicMock()
    mock_client_instance.chat.completions.create.side_effect = openai.APIStatusError(
        "API Error occurred", response=mock_response, body=None
    )

    result = call_llm(
        api_key="test-api-key",
        api_url="https://api.test.com",
        model="Mistral-7B-Instruct-v0.3",
        messages=[{"role": "user", "content": "Test message"}],
    )

    assert result is None
    mock_openai_client.assert_called_once_with(
        api_key="test-api-key", base_url="https://api.test.com"
    )


@patch("includes.utils.openai.OpenAI")
def test_call_llm_unexpected_error(mock_openai_client):
    """Test LLM API call with unexpected error"""
    mock_client_instance = mock_openai_client.return_value
    mock_client_instance.chat.completions.create.side_effect = Exception(
        "Unexpected error"
    )

    result = call_llm(
        api_key="test-api-key",
        api_url="https://api.test.com",
        model="Mistral-7B-Instruct-v0.3",
        messages=[{"role": "user", "content": "Test message"}],
    )

    assert result is None
    mock_openai_client.assert_called_once_with(
        api_key="test-api-key", base_url="https://api.test.com"
    )


def test_read_cve_from_kb_success(tests_path, tmp_path_factory):
    """Test successful CVE data building for LLM"""
    repo = TestRepo("llm", tests_path, tmp_path_factory)
    repo.commit(["2025/CVE-2025-1000.json"], hour=1, minute=00)

    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path):
        result = read_cve_from_kb("CVE-2025-1000")

    assert result == {
        "cve_id": "CVE-2025-1000",
        "created": "2025-05-05T20:55:46.335000+00:00",
        "title": "IBM Db2 denial of service",
        "description": "IBM Db2 for Linux, UNIX and Windows (includes DB2 Connect Server) 11.5.0 through 11.5.9 and 12.1.0 through 12.1.1 \n\ncould allow an authenticated user to cause a denial of service when connecting to a z/OS database due to improper handling of automatic client rerouting.",
        "vendors": ["ibm", "ibm$PRODUCT$db2"],
        "weaknesses": ["CWE-770"],
        "metrics": {
            "cvssV3_1": {
                "score": 5.3,
                "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H",
            },
            "epss": {"score": 0.00062},
            "ssvc": {
                "options": {
                    "Automatable": "no",
                    "Exploitation": "none",
                    "Technical Impact": "partial",
                },
                "version": "2.0.3",
            },
        },
    }


def test_read_cve_from_kb_with_missing_fields(tests_path, tmp_path_factory):
    """Test CVE data building for LLM with missing optional fields"""
    repo = TestRepo("llm", tests_path, tmp_path_factory)
    repo.commit(["2025/CVE-2025-9999.json"], hour=1, minute=00)

    # Mock the KB_LOCAL_REPO path to point to our test data
    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path):
        result = read_cve_from_kb("CVE-2025-9999")

    # Expected result
    expected = {
        "cve_id": "CVE-2025-9999",
        "created": "2025-01-15T10:30:00Z",
        "title": "Test CVE",
        "description": "Test description",
        "vendors": [],
        "weaknesses": [],
        "metrics": {},
    }

    assert result == expected


def test_build_scores_distribution():
    """Test build_scores_distribution with various score ranges"""
    scores = [
        {"score": "9.5", "count": 2},  # Critical
        {"score": "10.0", "count": 1},  # Critical
        {"score": "8.7", "count": 3},  # High
        {"score": "7.0", "count": 1},  # High
        {"score": "5.5", "count": 4},  # Medium
        {"score": "4.0", "count": 2},  # Medium
        {"score": "2.1", "count": 5},  # Low
        {"score": "0.1", "count": 1},  # Low
        {"score": "0.0", "count": 2},  # Unknown
        {"score": "null", "count": 3},  # Unknown
    ]

    result = build_scores_distribution(scores)
    expected = [
        "Critical: 3",
        "High: 4",
        "Medium: 6",
        "Low: 6",
        "Unknown: 5",
    ]
    assert result == expected


def test_build_scores_distribution_edge_cases():
    """Test build_scores_distribution with edge cases and invalid values"""
    scores = [
        {"score": "9.0", "count": 1},  # Critical
        {"score": "8.9", "count": 1},  # High
        {"score": "6.9", "count": 1},  # Medium
        {"score": "3.9", "count": 1},  # Low
        {"score": "invalid", "count": 2},  # Unknown
        {"score": "", "count": 1},  # Unknown
        {"score": "null", "count": 3},  # Unknown
    ]

    result = build_scores_distribution(scores)
    expected = [
        "Critical: 1",
        "High: 1",
        "Medium: 1",
        "Low: 1",
        "Unknown: 6",
    ]
    assert result == expected


def test_build_scores_distribution_empty():
    """Test build_scores_distribution with empty input"""
    result = build_scores_distribution([])
    expected = [
        "Critical: 0",
        "High: 0",
        "Medium: 0",
        "Low: 0",
        "Unknown: 0",
    ]
    assert result == expected


@patch("includes.utils.read_cve_from_kb")
def test_build_user_content_for_llm_basic(mock_read_cve):
    """Test build_user_content_for_llm with basic CVE data"""
    mock_read_cve.return_value = {
        "cve_id": "CVE-2024-0001",
        "created": "2024-01-01T10:00:00Z",
        "title": "Test CVE Title",
        "description": "Test CVE description",
        "vendors": ["vendor1", "vendor2$PRODUCT$product1"],
        "weaknesses": ["CWE-79", "CWE-89"],
        "metrics": {
            "cvssV3_1": {"score": 8.5},
            "epss": {"score": 0.05},
            "kev": True,
        },
    }

    report_cves = ["CVE-2024-0001"]
    report_cves_count = 1
    report_cves_score_distribution = [{"score": "8.5", "count": 1}]

    result = build_user_content_for_llm(
        report_cves, report_cves_count, report_cves_score_distribution
    )

    # Verify key components are present
    assert "=== Statistics ===" in result
    assert "Total CVEs: 1" in result
    assert (
        "CVSS Severity Distribution: Critical: 0, High: 1, Medium: 0, Low: 0, Unknown: 0"
        in result
    )
    assert "=== CVE #1 ===" in result
    assert "CVE-ID: CVE-2024-0001" in result
    assert "Created: 2024-01-01T10:00:00Z" in result
    assert "Title: Test CVE Title" in result
    assert "Vendors: vendor1, vendor2 (product1)" in result
    assert "Weaknesses: CWE-79, CWE-89" in result
    assert "Metrics: CVSS 8.5, EPSS 5%, KEV True" in result
    assert "Description: Test CVE description" in result

    mock_read_cve.assert_called_once_with("CVE-2024-0001")


@patch("includes.utils.read_cve_from_kb")
def test_build_user_content_for_llm_missing_fields(mock_read_cve):
    """Test build_user_content_for_llm with missing optional fields"""
    mock_read_cve.return_value = {
        "cve_id": "CVE-2024-0002",
        "created": "2024-01-02T10:00:00Z",
        "title": None,  # Missing title
        "description": "Test description",
        "vendors": [],  # Empty vendors
        "weaknesses": [],  # Empty weaknesses
        "metrics": {},  # Empty metrics
    }

    report_cves = ["CVE-2024-0002"]
    report_cves_count = 1
    report_cves_score_distribution = []

    result = build_user_content_for_llm(
        report_cves, report_cves_count, report_cves_score_distribution
    )

    assert "Title: [No title provided]" in result
    assert "Vendors: None listed" in result
    assert "Weaknesses: None listed" in result
    assert "Metrics: None available" in result


@patch("includes.utils.read_cve_from_kb")
def test_build_user_content_for_llm_many_vendors(mock_read_cve):
    """Test build_user_content_for_llm with many vendors (truncation)"""
    # Create 20 vendors to test truncation at 15
    vendors = [f"vendor{i}" for i in range(20)]

    mock_read_cve.return_value = {
        "cve_id": "CVE-2024-0003",
        "created": "2024-01-03T10:00:00Z",
        "title": "Test CVE",
        "description": "Test description",
        "vendors": vendors,
        "weaknesses": ["CWE-79"],
        "metrics": {"cvssV3_1": {"score": 5.0}},
    }

    report_cves = ["CVE-2024-0003"]
    report_cves_count = 1
    report_cves_score_distribution = [{"score": "5.0", "count": 1}]

    result = build_user_content_for_llm(
        report_cves, report_cves_count, report_cves_score_distribution
    )

    # Should show first 15 vendors plus truncation message
    assert "vendor0, vendor1" in result
    assert "vendor14" in result
    assert "... (and 5 more)" in result


@patch("includes.utils.read_cve_from_kb")
def test_build_user_content_for_llm_multiple_cves(mock_read_cve):
    """Test build_user_content_for_llm with multiple CVEs"""

    def mock_cve_data(cve_id):
        return {
            "cve_id": cve_id,
            "created": "2024-01-01T10:00:00Z",
            "title": f"Title for {cve_id}",
            "description": f"Description for {cve_id}",
            "vendors": ["vendor1"],
            "weaknesses": ["CWE-79"],
            "metrics": {"cvssV3_1": {"score": 7.5}},
        }

    mock_read_cve.side_effect = lambda cve_id: mock_cve_data(cve_id)

    report_cves = ["CVE-2024-0001", "CVE-2024-0002"]
    report_cves_count = 2
    report_cves_score_distribution = [{"score": "7.5", "count": 2}]

    result = build_user_content_for_llm(
        report_cves, report_cves_count, report_cves_score_distribution
    )

    assert "Total CVEs: 2" in result
    assert "=== CVE #1 ===" in result
    assert "=== CVE #2 ===" in result
    assert "CVE-ID: CVE-2024-0001" in result
    assert "CVE-ID: CVE-2024-0002" in result

    # Verify both CVEs were read
    assert mock_read_cve.call_count == 2


@patch("includes.utils.read_cve_from_kb")
def test_build_user_content_for_llm_epss_formatting(mock_read_cve):
    """Test build_user_content_for_llm with different EPSS score formats"""
    mock_read_cve.return_value = {
        "cve_id": "CVE-2024-0004",
        "created": "2024-01-04T10:00:00Z",
        "title": "Test CVE",
        "description": "Test description",
        "vendors": ["vendor1"],
        "weaknesses": ["CWE-79"],
        "metrics": {
            "cvssV3_1": {"score": 6.0},
            "epss": {"score": 0.001},  # Should format as "< 1%"
        },
    }

    report_cves = ["CVE-2024-0004"]
    report_cves_count = 1
    report_cves_score_distribution = [{"score": "6.0", "count": 1}]

    result = build_user_content_for_llm(
        report_cves, report_cves_count, report_cves_score_distribution
    )

    assert "EPSS < 1%" in result
