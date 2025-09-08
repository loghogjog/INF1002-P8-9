# Git Workflow Cheatsheet

This guide shows the git commands for contributing to this repository.

---

## Clone the Repository (first time only)
```bash
git clone git@github.com:ORG_NAME/REPO_NAME.git
cd REPO_NAME

git checkout main #switch to main branch
git pull origin main

git checkout -b [name_of_branch] # -b creates a new branch

git add . # . adds all files. use the name of the file instead if you only want to commit one specific file

git commit -m "[short_discription_of_commit]"

git push -u origin [name_of_branch]

```

---

## Open a Pull Request (PR)
```bash
Go to the repository on GitHub.

GitHub will show a banner: “Compare & pull request” → click it.


Fill in the PR template:

Title: short summary (feat: add .eml upload form)


Description: what you changed + how to test


Submit the PR (target branch = main).
```

---

## Before Pushing Any Commits (IMPORTANT)
## Always pull before you push, then open a PR
```bash
git fetch origin
git checkout [name_of_branch]
git merge origin/main

# resolve conflicts if needed, then:

git add [file]
git commit
git push
```

---

