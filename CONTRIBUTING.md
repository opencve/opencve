# Contributing to OpenCVE

First of all, thank you for your interest in contributing to OpenCVE.

OpenCVE is an source-available project, and we welcome contributions that improve the community edition: bug fixes, documentation improvements, tests, performance improvements, UI/UX improvements, integrations, and features that fit the scope of the open source project.

## Before opening a large pull request

If you plan to work on a significant feature, please open an issue or discussion first.

This helps us avoid situations where contributors spend time on a feature that may not be merged because it does not fit the project direction, architecture, maintenance expectations, or product roadmap.

Examples of changes that should be discussed before implementation:

* new authentication mechanisms,
* organization or multi-tenant features,
* permission and role management changes,
* notification backends,
* database schema changes,
* large UI changes,
* major dependency additions,
* features requiring new infrastructure or operational assumptions.

Small bug fixes, documentation improvements, tests, and minor cleanups usually do not require prior discussion.

## Project scope

OpenCVE follows an open-core model.

The community edition focuses on the core vulnerability monitoring experience: tracking CVEs, vendors and products, receiving notifications, and managing vulnerability-related workflows.

Some features are intentionally kept outside of the community edition and may be part of OpenCVE.io or commercial offerings. This includes, but is not limited to, some organization-oriented, enterprise, SSO, identity-management, access-control, compliance, and administration features.

This model helps us keep the project sustainable while continuing to maintain and improve the community edition.

## Pull request expectations

Before submitting a pull request, please make sure that:

* the change is aligned with the project scope,
* the implementation is reasonably small and maintainable,
* tests are included when relevant,
* documentation is updated when behavior changes,
* new dependencies are justified,
* the pull request description explains the motivation and trade-offs.

We may decline a pull request even if it is technically correct, especially if it adds maintenance burden, changes the product direction, overlaps with commercial features, or does not fit the roadmap.

When this happens, we will do our best to explain the reason clearly and respectfully.

## Development setup

Please refer to the project documentation for local setup instructions.

Before opening a pull request, run the test suite and formatting/linting tools used by the project.

## License

By contributing to OpenCVE, you agree that your contributions will be licensed under the same license as the project.
