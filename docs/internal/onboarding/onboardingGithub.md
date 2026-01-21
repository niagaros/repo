# GitHub Onboarding Guide (Repository Access)

This guide explains how to onboard a new team member and grant them access to the required GitHub repository.

---

## Step 1 — Ensure the User Has a GitHub Account
Before granting access, confirm that the user has a GitHub account.

If not, ask them to:
1. Go to https://github.com
2. Click **Sign up**
3. Create an account using:
   - Email
   - Username
   - Password
4. Verify their email address

Once the account is created, proceed to the next step.

---

## Step 2 — Send the Repository Invitation
Invite the user to the repository or organization.

1. Open the GitHub repository or organization
2. Navigate to **Settings**
3. Select **Collaborators & teams** (or **People** for organizations)
4. Add the user using their **GitHub username or email**
5. Send the invitation

The user will receive an invite link by email and on GitHub.

---

## Step 3 — User Accepts the Repository Invitation
Ask the user to accept the invitation.

1. The user opens the **GitHub invite link**
2. Signs in to GitHub if prompted
3. Clicks **Accept invitation**
4. Waits a few seconds for access to be applied

The user is now a member of the repository or organization.

---

## Step 4 — Assign the User to the Correct Group / Team
After the invitation is accepted, assign the user to the appropriate group to grant correct permissions.

1. Go to the **Organization settings**
2. Open **Teams**
3. Select the appropriate team (e.g. `Developers`, `Maintainers`, `Read-Only`)
4. Add the user to the team
5. Verify the team has the correct repository permissions

This ensures access is managed via groups rather than individual permissions.

---

## Step 5 — User Opens the Repository
Once access is configured, the user can access the repository.

1. Go to https://github.com
2. Click the **profile icon** (top right)
3. Select **Your repositories**
4. Open the assigned repository

---

## Step 6 — Verify Access
Confirm the user can perform the expected actions:
- View repository code
- Clone the repository
- Create branches
- Open pull requests (based on assigned permissions)

If the user cannot perform an action, double-check:
- Team assignment
- Repository permissions
- Branch protection rules

---

## Notes
- Always assign permissions via **teams/groups**, not individual users.
- Changes to access should be made at the group level where possible.
- Remove users from teams when offboarding to automatically revoke access.
