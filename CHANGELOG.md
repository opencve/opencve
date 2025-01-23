# Changelog

## 2.1.0 - 2025-01-23
### Added
- Add CVEs advanced search feature
- Improve install.sh script
- Add new DAG to check SMTP configuration
- Add custom 404 and 500 pages
- Upgrade web & scheduler dependencies
- Add canonical urls in html
- Add the statistics view
- Add variables model
- Update title and description of HTML pages
- Add start_tls setting for SMTP configuration of scheduler

### Fixed
- Disallow null character in query params
- Add Allauth socialaccount dependency
- Remove syntax warning

### Removed
- Remove Python 3.9 support

## 2.0.0 - 2024-12-10
Welcome to OpenCVE v2!

Check out the [release notes](https://github.com/opencve/opencve/releases/tag/v2.0.0) to discover all the new features and improvements in this major update.

## 1.5.0 - 2023-12-10
### Added
- Support the new NVD API data feed

## 1.4.1 - 2023-05-26
### Added
- Add the cve.org link in CVE html page

### Fixed
- Upgrade jsmin package to fix a dependency issue

## 1.4.0 - 2022-11-05
### Added
- Add vendor name in products subscriptions
- Add a periodic task to clean old reports
- Increase performance with indexes on reports and alerts tables
- Support the MAIL_USE_SSL configuration
- Show subscribed users for vendors and products in admin
- Add column_filters in admin views
- Include custom HTML code in all pages for analytics

### Fixed
- Remove duplicates items when pagination is used
- Add a lock in Celery tasks to avoid parallel chains
- Downgrade importlib-metadata to fix a bug in Python 3.7
- Parse modified references with quote in url
- Fix responsive bug in login and register views
- Fix a bug when viewing emails in Outlook
- Rework CPE parsing to improve memory footprint
- Release memory when possible in CVE import

### Removed
- Remove Python 3.6 support

## 1.3.0 - 2022-01-22
### Added
- feat: add tags in dashboard
- feat: display the change details in a dedicated view
- feat: display all activities (not only subscriptions ones)
- feat: add the first_time event
- feat: display change date in a human format in CVE history
- feat: add new API endpoint to search products without vendor
- feat: improve the vendors and products search
- feat: display recorded change history for CVEs

### Fixed
- fix: missing template for the first_time event
- fix: check uuid validity before searching the change

## 1.2.3 - 2021-08-31

### Fixed
- fix: sort the activities in homepage and increase performance of SQL query

## 1.2.2 - 2021-08-12

### Fixed
- fix: reduce the list of reports to 5 items in homepage
- fix: remove hardcoded date and number of report alerts in homepage

## 1.2.1 - 2021-08-11
### Added
- tests: add tests on subscriptions controller
- tests: added test for admin
- feat: better JSON diff in admin view
- feat: add the last CVE activities in homepage
- tests: add tests on last activities feature

### Fixed
- fix: improve error messages in create-user command
- fix: subscribe to invalid ID throws 400 instead of 500 error

## 1.2.0 - 2021-06-19
### Added
- Improved search functionality on /cve
- Add GIN indexes on cves.summary and cves.cve_id
- New API Endpoint (user subscriptions)
- Add the tags feature

### Fixed
- trim() the text of the 'Subscribe' button
- CVE can be filtered by CWE and vendor in the same query
- Default tag color wasn't correctly handled

## 1.1.0 - 2021-04-11
### Added
- Display vulnerability type with the CWE ID
- Add more statistics in admin dashboard
- Add opencve-docker repository link
- Release the API
- Return API datetimes in ISO8601
- Add API ratelimit

### Fixed
- Check if email is unique when editing a profile
- Check search attribute instead of id in CWEs listing
- Fix "stmp_password" in configuration, ensure compatibility before deprecating it

## 1.0.2 - 2021-01-18
### Added
- Refactor the reports task to make it more testable
- Add Github issue templates
- Add the NONE and CRITICAL CVSSv3 filters
- Add Python 3.8 in setup.py classifiers
- Add favicon.ico in website root

### Fixed
- Redirect subscribe links to the login page for unauthenticated users
- Fix wrong links for CWE definitions
- Handle exception in case of bad SMTP configuration
- Fix user creation/edition in administration panel
- Make Cwe.cwe_id field not nullable
- Clean CVSSv2 and CVSSv3 fields for rejected CVEs

## 1.0.1 - 2021-01-03
### Added
- Add an admin link in the user menu
- Display the is_confirmed field in users list
- Use click prompt to ask the user password

### Fixed
- Add missing javascript files
- Display the resend confirmation link in flash message
- Add email validator in profile form
- Click on search button submits the request
- Display the excerpt list of vendors and products in CVEs listing

## 1.0.0 - 2020-12-28
### Added
- Initial release.
