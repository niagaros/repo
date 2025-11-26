# Branch Management Documentation

## Purpose
This document describes how branch protection and workflow rules are applied in the repository.  
It ensures safe, consistent development and prevents accidental changes to critical branches.

---

## Branch Overview
| Branch | Purpose |
|---------|----------|
| `main` | Production-ready code; reflects what is deployed live. |
| `acceptance` | Staging environment; used for final testing before production. |
| `feature/*` | Temporary branches for new features, bug fixes, or experiments. |

---

## Branch Ruleset Summary

### Location
Settings are in GitHub under:  
**Settings → Rulesets**  
Applied to the branches:
- `main`
- `acceptance`

### Configured Rules

1. **Restrict updates**  
   Prevents anyone from pushing directly to the branch.  
   Changes must be made via a pull request.

2. **Restrict deletions**  
   Protects the branch from being deleted.  
   The branch cannot be removed accidentally or manually.

3. **Require linear history**  
   Ensures the commit history remains straight.  
   Merge commits are not allowed.

4. **Require a pull request before merging**  
   All commits must be added via a pull request.  
   Direct commits to `main` or `acceptance` are not allowed.

5. **Block force pushes**  
   Blocks force pushes.  
   Prevents overwriting the branch history.

### Summary
Both branches (`main` and `acceptance`) are protected.  
No one can push directly, delete, or force push.  
All changes must go through a pull request, and the commit history remains linear.

---

## Pull Request Workflow

1. Create a new branch from `acceptance`, named following the convention:  
   `feature/<short-description>` or `bugfix/<short-description>`.
2. Implement and commit your changes in that branch.
3. Open a **Pull Request (PR)** from your feature branch into `acceptance`.
4. After review and testing, open a PR from `acceptance` into `main` for production deployment.
5. Merges are only performed via approved pull requests — never direct commits.

---

## Summary
This workflow ensures:
- Protected branches cannot be altered directly.  
- Code is reviewed and tested before reaching production.  
- The commit history stays clean and traceable.  
- Feature work is isolated and safely integrated through pull requests.
