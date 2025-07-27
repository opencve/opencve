# RSS Feed Feature

## Overview

The RSS feed feature allows users to subscribe to CVE updates via RSS feeds. This provides an alternative to email and webhook notifications, allowing users to receive updates in their favorite RSS reader.

## Features

- **User Feed**: Shows all CVEs related to all projects the user has access to
- **Project Feed**: Shows CVEs related to a specific project
- **Token-based Authentication**: Secure access to feeds without requiring a login session
- **Token Management**: Users can create, view, and delete tokens

## Usage

### Creating a Feed Token

Before you can use RSS feeds, you need to create a feed token:

1. Log in to your OpenCVE account
2. Click on your username in the top-right corner
3. Select "RSS Feeds" from the dropdown menu
4. On the RSS Feed Management page, enter a name for your token (e.g., "My RSS Reader")
5. Click "Create Token"

### Accessing Your Feeds

Once you have created a token, you can access your feeds using the following URLs:

#### User Feed

This feed includes all CVE changes related to all your project subscriptions:

```
https://your-opencve-instance.com/rss/feed/YOUR_TOKEN/
```

Replace `YOUR_TOKEN` with the token you created.

#### Project Feed

This feed includes only CVE changes related to a specific project:

```
https://your-opencve-instance.com/rss/feed/YOUR_TOKEN/ORGANIZATION_NAME/PROJECT_NAME/
```

Replace `YOUR_TOKEN`, `ORGANIZATION_NAME`, and `PROJECT_NAME` with your actual values.

### Managing Feed Tokens

You can view all your feed tokens on the RSS Feed Management page:

1. Log in to your OpenCVE account
2. Click on your username in the top-right corner
3. Select "RSS Feeds" from the dropdown menu

If you no longer need a token or suspect it has been compromised, you can delete it:

1. Go to the RSS Feed Management page
2. Find the token you want to delete
3. Click the "Delete" button
4. Confirm the deletion

**Note:** Deleting a token will invalidate any RSS feed URLs using that token. You will need to create a new token and update your RSS reader with the new URL.

## Feed Content

The RSS feeds include the following information for each CVE:

- CVE ID
- Title (if available)
- Description
- CVSS v3.1 Score (if available)
- Changes detected
- Affected vendors/products
- Link to the CVE details page

## Technical Details

The RSS feed feature is implemented using Django's syndication framework. It uses a token-based authentication system to secure the feeds while allowing access from RSS readers without requiring a login session.

### Models

- `FeedToken`: Stores the tokens used for authentication

### Views

- `FeedTokenListView`: Lists all tokens for the current user
- `FeedTokenCreateView`: Creates a new token
- `FeedTokenDeleteView`: Deletes a token
- `UserFeed`: Feed for all CVEs related to all projects the user has access to
- `ProjectFeed`: Feed for CVEs related to a specific project

### URLs

- `/rss/`: Token management page
- `/rss/feed/<token>/`: User feed with all CVEs
- `/rss/feed/<token>/<org_name>/<project_name>/`: Project-specific feed

### Security

- Tokens are generated using Python's `secrets` module, which provides cryptographically secure random numbers
- Tokens are 64 characters long, making them practically impossible to guess
- Users can revoke tokens at any time via the token management UI