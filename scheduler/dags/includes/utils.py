import json
import pathlib
from logging import Logger
from typing import Dict, List, Optional, Tuple

import more_itertools

import openai
from airflow.configuration import conf
from airflow.exceptions import AirflowException, AirflowConfigException
from airflow.models import Variable
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate
from git.objects.commit import Commit
from git.repo import Repo
from includes.constants import KB_LOCAL_REPO
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pendulum.datetime import DateTime


def divide_list(iterable, n):
    """
    Divide a list into n chunks.

    Examples:
      >>> divide_list(["a", "b", "c", "d"], 5)
      >>> [["a"], ["b"], ["c"], ["d"]]
      >>> divide_list(["a", "b", "c", "d"], 3)
      >>> [["a", "b"], ["c"], ["d"]]
    """
    if len(iterable) <= n:
        return [[p] for p in iterable]

    new_list = []
    for chunk in more_itertools.divide(n, iterable):
        new_list.append(list(chunk))

    return new_list


def group_changes_by_vendor(records):
    """
    This function groups changes by vendors.
    """
    vendors_changes = {}

    for record in records:
        change_id = record[0]
        vendors = record[3]
        for vendor in vendors:
            if vendor not in vendors_changes:
                vendors_changes[vendor] = []
            vendors_changes[vendor].append(change_id)

    return vendors_changes


def format_change_details(records):
    """
    This function transform a list of changes into a dictionary
    """
    return {
        r[0]: {
            "change_id": r[0],
            "change_types": r[1],
            "change_path": r[2],
            "cve_vendors": r[3],
            "cve_id": r[4],
            "cve_metrics": r[5],
        }
        for r in records
    }


def merge_project_subscriptions(records):
    """
    This function returns a list of projects with their associated
    vendors and products.
    """
    projects_subscriptions = {}
    for project in records:
        vendors = project[1]["vendors"] + project[1]["products"]
        if vendors:
            projects_subscriptions[project[0]] = vendors
    return projects_subscriptions


def list_changes_by_project(changes, subscriptions):
    """
    This associates the project subscriptions with their changes.

    Example:
        >>> changes = {
            'vendor1': ['change-uuid-1'],
            'vendor2': ['change-uuid-1', 'change-uuid-2']
        }
        >>> subscriptions = {
            'project-uuid-1': ['vendor1', 'vendor2', 'vendor$PRODUCT$product']
        }
        >>> list_changes_by_project(changes, subscriptions)
        {
            "project-uuid-1": [
                "change-uuid-1",
                "change-uuid-2"
            ]
        }
    """
    projects_changes = {}
    for project, subscriptions in subscriptions.items():

        # Skip the project if no subscription
        if not subscriptions:
            continue

        projects_changes[project] = set()
        for subscription in subscriptions:
            if subscription in changes.keys():
                projects_changes[project].update(changes[subscription])
        projects_changes[project] = list(projects_changes[project])

    return {k: v for k, v in projects_changes.items() if v}


def group_notifications_by_project(records, subscriptions):
    projects_notifications = {}
    for notification in records:
        p_id, p_name, o_name, n_name, n_type, n_conf = notification

        if p_id not in projects_notifications:
            projects_notifications[p_id] = []

        # Extract project subscriptions
        project_subscriptions = subscriptions.get(p_id, [])

        projects_notifications[p_id].append(
            {
                "project_id": p_id,
                "project_name": p_name,
                "project_subscriptions": project_subscriptions,
                "organization_name": o_name,
                "notification_name": n_name,
                "notification_type": n_type,
                "notification_conf": n_conf,
            }
        )
    return projects_notifications


def get_dates_from_context(context: Dict) -> Tuple[DateTime, DateTime]:
    start = context.get("data_interval_start")
    end = context.get("data_interval_end").subtract(seconds=1)
    return start, end


def list_commits(logger: Logger, start: DateTime, end: DateTime) -> List[Commit]:
    logger.info("Reading %s repository", KB_LOCAL_REPO)
    repo_path = pathlib.Path(KB_LOCAL_REPO)

    if not all([start, end]):
        raise AirflowException("Start and end intervals must be set")

    # Each DagRun only parses its associated commits (schedule is hourly).
    # We'll use the interval dates to list commits during this period, but
    # git log --before and --after options are both included, so we need to
    # subtract 1 second to the end date in order to avoid duplicates commits.
    end = end.subtract(seconds=1)

    logger.info("Listing commits between %s and %s", start, end)
    repo = Repo(repo_path)
    commits = list(repo.iter_commits(after=start, before=end, reverse=True))

    if not commits:
        logger.info("No commit found")
        return []

    # Iterate over all commits
    logger.info(
        "Found %s commit(s), from %s to %s",
        str(len(commits)),
        commits[0],
        commits[-1],
    )

    return commits


async def get_smtp_message(email_to, subject, template, context):
    dags_folder = pathlib.Path(conf.get("core", "dags_folder"))
    env = Environment(
        loader=FileSystemLoader(dags_folder / "templates"),
        autoescape=select_autoescape(),
        enable_async=True,
    )

    # Generate the messages to send
    message = MIMEMultipart("alternative")
    message["From"] = conf.get("opencve", "notification_smtp_mail_from")
    message["To"] = email_to
    message["Subject"] = subject
    message["Date"] = formatdate()

    plain_text_template = env.get_template(f"{template}.txt")
    plain_text_rendered = await plain_text_template.render_async(**context)
    plain_text_message = MIMEText(plain_text_rendered, "plain", "utf-8")

    html_template = env.get_template(f"{template}.html")
    html_rendered = await html_template.render_async(**context)
    html_message = MIMEText(html_rendered, "html", "utf-8")

    message.attach(plain_text_message)
    message.attach(html_message)

    return message


def get_smtp_conf():
    kwargs = {
        "hostname": conf.get("opencve", "notification_smtp_host"),
        "port": conf.getint("opencve", "notification_smtp_port"),
        "use_tls": conf.getboolean("opencve", "notification_smtp_use_tls"),
        "validate_certs": conf.getboolean(
            "opencve", "notification_smtp_validate_certs"
        ),
        "timeout": conf.getint("opencve", "notification_smtp_timeout"),
    }

    # Support empty values for username and password
    username = conf.get("opencve", "notification_smtp_user")
    if username:
        kwargs["username"] = username

    password = conf.get("opencve", "notification_smtp_password")
    if password:
        kwargs["password"] = password

    try:
        start_tls = conf.getboolean("opencve", "notification_smtp_start_tls")
        kwargs["start_tls"] = start_tls
    except AirflowConfigException:
        pass

    return kwargs


def should_execute(variable_name: str) -> bool:
    """
    This function checks if a variable is set to "true".
    """
    return Variable.get(variable_name, default_var="true") == "true"


def call_llm(
    api_key: str, api_url: str, model: str, messages: List[Dict]
) -> Optional[str]:
    client = openai.OpenAI(api_key=api_key, base_url=api_url)
    try:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
        )
    except openai.RateLimitError as e:
        print(f"Rate limit exceeded: {e}")
        return None

    except openai.APIError as e:
        print(f"API Error: {e}")
        return None

    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

    return response.choices[0].message.content


def format_epss_score(score: float) -> str:
    """Formats EPSS score as a percentage string."""
    if not isinstance(score, (int, float)):
        return "N/A"
    if score == 0:
        return "0%"
    if 0 < score < 0.01:
        return "< 1%"
    return f"{score * 100:.0f}%"


def read_cve_from_kb(cve_id: str) -> Dict:
    """
    This function reads the CVE data from the KB local repo and
    build a payload for the LLM.
    """
    year = cve_id.split("-")[1]
    file_path = f"{year}/{cve_id}.json"
    with open(pathlib.Path(KB_LOCAL_REPO) / file_path) as f:
        cve_data = json.load(f)

    kb_opencve_data = cve_data.get("opencve", {})

    # Clean the data to reduce the size of the payload
    # because the LLM is not able to handle large payloads
    opencve_data = {
        "cve_id": cve_id,
        "created": kb_opencve_data.get("created", {}).get("data", None),
        "title": kb_opencve_data.get("title", {}).get("data", None),
        "description": kb_opencve_data.get("description", {}).get("data", None),
        "vendors": kb_opencve_data.get("vendors", {}).get("data", []),
        "weaknesses": kb_opencve_data.get("weaknesses", {}).get("data", []),
        "metrics": {},
    }

    metrics = kb_opencve_data.get("metrics", {})
    for key, value in metrics.items():
        metric_data = value.get("data", {})
        if metric_data:
            opencve_data["metrics"][key] = metric_data

    return opencve_data


def build_scores_distribution(scores):
    categories = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Unknown": 0,
    }
    for score in scores:
        score_str = score["score"]
        count = score["count"]

        if score_str == "null":
            categories["Unknown"] += count
            continue

        try:
            score_float = float(score_str)
            if 9.0 <= score_float <= 10.0:
                categories["Critical"] += count
            elif 7.0 <= score_float <= 8.9:
                categories["High"] += count
            elif 4.0 <= score_float <= 6.9:
                categories["Medium"] += count
            elif 0.1 <= score_float <= 3.9:
                categories["Low"] += count
            else:  # 0.0 or other cases
                categories["Unknown"] += count
        except (ValueError, TypeError):
            categories["Unknown"] += count

    distribution_parts = []
    distribution_parts.append(f"Critical: {categories['Critical']}")
    distribution_parts.append(f"High: {categories['High']}")
    distribution_parts.append(f"Medium: {categories['Medium']}")
    distribution_parts.append(f"Low: {categories['Low']}")
    distribution_parts.append(f"Unknown: {categories['Unknown']}")

    return distribution_parts


def build_user_content_for_llm(
    report_cves, report_cves_count, report_cves_score_distribution
):
    """
    This function loads the user content for the LLM.
    """
    text_output = []

    # Process the statistics
    text_output.append("=== Statistics ===")
    text_output.append(f"Total CVEs: {report_cves_count}")
    text_output.append(
        f"CVSS Severity Distribution: {', '.join(build_scores_distribution(report_cves_score_distribution))}"
    )

    # Process the CVEs
    cve_list = [read_cve_from_kb(cve) for cve in report_cves]
    for i, cve in enumerate(cve_list, 1):
        text_output.append(f"=== CVE #{i} ===")
        text_output.append(f"CVE-ID: {cve.get('cve_id', 'N/A')}")

        created = cve.get("created", "N/A")
        text_output.append(f"Created: {created}")

        title = cve.get("title")
        text_output.append(f"Title: {title or '[No title provided]'}")

        # Vendors
        vendors = cve.get("vendors", [])
        if vendors:
            formatted_vendors = []
            vendors_to_process = vendors[:15]

            for vendor in vendors_to_process:
                if "$PRODUCT$" in vendor:
                    parts = vendor.split("$PRODUCT$")
                    if len(parts) == 2:
                        vendor_name, product_name = parts
                        formatted_vendors.append(
                            f"{vendor_name.strip()} ({product_name.strip()})"
                        )
                    else:
                        formatted_vendors.append(vendor)
                else:
                    formatted_vendors.append(vendor)

            vendor_list_str = ", ".join(formatted_vendors)
            if len(vendors) > 15:
                vendor_list_str += f", ... (and {len(vendors) - 15} more)"

            text_output.append(f"Vendors: {vendor_list_str}")
        else:
            text_output.append("Vendors: None listed")

        # Weaknesses
        weaknesses = cve.get("weaknesses", [])
        if weaknesses:
            text_output.append(f"Weaknesses: {', '.join(weaknesses)}")
        else:
            text_output.append("Weaknesses: None listed")

        # Metrics
        metrics = cve.get("metrics", {})
        if metrics:
            metric_parts = []

            cvss_v3 = metrics.get("cvssV3_1", {})
            if cvss_v3 and "score" in cvss_v3:
                metric_parts.append(f"CVSS {cvss_v3['score']}")

            epss = metrics.get("epss", {})
            if epss and "score" in epss:
                epss_score_value = epss.get("score")
                formatted_epss = format_epss_score(epss_score_value)
                metric_parts.append(f"EPSS {formatted_epss}")

            kev_present = bool(metrics.get("kev"))
            metric_parts.append(f"KEV {kev_present}")

            text_output.append(f"Metrics: {', '.join(metric_parts)}")
        else:
            text_output.append("Metrics: None available")

        # Description
        description = cve.get("description", "N/A")
        text_output.append(f"Description: {description}")

        text_output.append("")  # Empty line between CVEs

    return "\n".join(text_output)
