# Changelog

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
