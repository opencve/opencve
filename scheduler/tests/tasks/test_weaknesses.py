from unittest.mock import patch

import pendulum
import pytest

from includes.tasks.weaknesses import sync_weaknesses

MOCK_WEAKNESSES = [
    {
        "id": "79",
        "name": "Cross-site Scripting",
        "description": "Test XSS description",
    },
    {
        "id": "89",
        "name": "SQL Injection",
        "description": "Test SQLi description",
    },
]

SYNC_DATE = pendulum.datetime(2026, 6, 8, 3, 0, tz="UTC")


@pytest.mark.web_db
def test_sync_weaknesses_inserts_records(web_pg_hook):
    """Test sync_weaknesses inserts weakness records via weakness_upsert."""
    with patch(
        "includes.tasks.weaknesses.fetch_weaknesses", return_value=MOCK_WEAKNESSES
    ):
        sync_weaknesses.function(logical_date=SYNC_DATE)

    records = web_pg_hook.get_records(
        "SELECT cwe_id, name, description FROM opencve_weaknesses ORDER BY cwe_id;"
    )
    assert records == [
        ("CWE-79", "Cross-site Scripting", "Test XSS description"),
        ("CWE-89", "SQL Injection", "Test SQLi description"),
    ]


@pytest.mark.web_db
def test_sync_weaknesses_upsert_preserves_created_at(web_pg_hook):
    """Test sync_weaknesses updates existing weaknesses without changing created_at."""
    created_at = pendulum.datetime(2020, 1, 1, 0, 0, tz="UTC")
    web_pg_hook.run(
        """
        INSERT INTO opencve_weaknesses (id, created_at, updated_at, cwe_id, name, description)
        VALUES (uuid_generate_v4(), %s, %s, %s, %s, %s);
        """,
        parameters=(
            created_at,
            created_at,
            "CWE-79",
            "Old name",
            "Old description",
        ),
    )

    with patch(
        "includes.tasks.weaknesses.fetch_weaknesses",
        return_value=[MOCK_WEAKNESSES[0]],
    ):
        sync_weaknesses.function(logical_date=SYNC_DATE)

    record = web_pg_hook.get_records(
        """
        SELECT created_at, updated_at, name, description
        FROM opencve_weaknesses
        WHERE cwe_id = 'CWE-79';
        """
    )[0]
    assert record[0] == created_at
    assert record[1] == SYNC_DATE
    assert record[2] == "Cross-site Scripting"
    assert record[3] == "Test XSS description"
