from unittest.mock import patch

import pendulum
import pytest
from airflow.utils.state import TaskInstanceState
from email.mime.multipart import MIMEMultipart

from includes.tasks.smtp import run


@pytest.mark.airflow_db
def test_dag_check_smtp_run_task(run_dag_task, override_confs):
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

    with patch("includes.tasks.smtp.aiosmtplib.send") as mock_send:
        with patch("includes.tasks.smtp.get_smtp_message") as mock_message:
            message = MIMEMultipart("alternative")
            mock_message.return_value = message

            task = run_dag_task(
                task_fn=run,
                start=pendulum.datetime(2025, 1, 1, 2, 0, tz="UTC"),
                end=pendulum.datetime(2025, 1, 1, 3, 0, tz="UTC"),
                params={"email": "foo@bar.com"},
            )

            assert task.state == TaskInstanceState.SUCCESS
            mock_send.assert_called_with(
                message,
                hostname="smtp.example.com",
                port=587,
                use_tls=True,
                validate_certs=True,
                timeout=30,
            )
