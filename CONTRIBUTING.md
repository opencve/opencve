# Contributing to OpenCVE

Thank you for your interest in contributing to OpenCVE!

OpenCVE is a source-available project, and we welcome contributions that improve the Community edition: bug fixes, documentation, tests, performance improvements, UI/UX improvements, integrations, and new features that fit the project scope.

Whether this is your first contribution or you already know the project well, we're happy to hear your ideas.

## Before you start

Small, focused bug fixes, documentation corrections and tests can usually be submitted directly.

For new features or significant changes to existing behavior, please discuss your idea with the maintainers before starting implementation. If an issue already exists, leave a comment explaining what you would like to do and your proposed approach. Otherwise, open an issue.

Please wait for maintainer agreement before moving ahead with significant work. An existing issue describes a need or a problem, but it does not necessarily mean that we have agreed on a solution or decided to prioritize it.

Discussing the approach first helps us align contributions with the roadmap, avoid overlapping work, and save you time on changes that might need a different direction.

Changes worth discussing in advance include:

- new features, search capabilities or API behavior;
- authentication, permissions and organization management;
- notification backends and integrations;
- database schema changes;
- significant UI changes;
- major dependencies or new infrastructure requirements.

If you're unsure whether your change needs a discussion, feel free to ask. A short explanation is enough to get started.

## Working together

We are a small team balancing development, maintenance, support and contribution reviews.

If you have several ideas, please coordinate with us before opening multiple unrelated PRs. Starting with one focused contribution gives us a chance to provide feedback and agree on what would be most useful next.

We review contributions according to project priorities and available time, so feedback may take a while. We cannot promise a review timeline or guarantee that every PR will be merged, but we appreciate the time and effort behind each contribution.

Sometimes a useful, technically sound change may need to wait or take a different direction because of the roadmap or its maintenance implications. When that happens, we will do our best to explain why.

## Project scope

OpenCVE follows an open-core model.

The Community edition focuses on the core vulnerability monitoring experience: tracking CVEs, vendors and products, receiving notifications, and managing vulnerability-related workflows.

Some features are intentionally kept outside of the Community edition and may be part of OpenCVE.io or commercial offerings. This includes some enterprise, identity-management, access-control, compliance, and administration capabilities.

This model helps us keep the project sustainable while continuing to improve the Community edition.

If you're unsure whether an idea fits the Community edition, let's discuss it before you invest time in implementing it.

## Preparing your pull request

A focused PR is easier to review and more likely to move forward smoothly.

Please aim to:

- address one clearly defined problem;
- keep the implementation reasonably small and maintainable;
- avoid unrelated refactoring or formatting changes;
- include tests when relevant;
- update documentation when behavior changes;
- explain any new dependencies.

Your PR description should briefly explain:

- the problem or use case;
- what you changed and why;
- how you tested it;
- any relevant trade-offs or limitations.

For bug fixes, reproduction steps or a regression test are especially helpful. If you couldn't run a check, simply mention it.

Please review your complete diff before submitting and be ready to discuss your implementation or make adjustments during review.

## AI-assisted contributions

You're welcome to use AI tools when contributing to OpenCVE.

With the growing availability of these tools, proposing changes has become faster, while reviewing and maintaining them still takes time. The coordination and quality expectations above apply equally to contributions made with or without AI assistance.

If AI helped produce a substantial part of your contribution, briefly mention how you used it in the PR description.

Before submitting, please make sure that you:

- have personally read these contributing guidelines;
- understand the changes and can explain your implementation choices;
- have checked that the proposed solution addresses the problem;
- have verified the technical explanations and testing claims in your PR.

Please use AI to support your contribution while keeping responsibility for the result. A focused, verified change is more helpful than a large volume of submissions.

## Development setup

Please refer to the [project documentation](https://docs.opencve.io/) for local setup instructions.

Before opening a PR, run the relevant tests and formatting/linting tools used by the project. If you run into difficulties setting up the environment, let us know what you tried and where you got stuck.

## License

By contributing to OpenCVE, you agree that your contributions will be licensed under the same license as the project.

Please ensure that you have the right to submit any content included in your contribution.
