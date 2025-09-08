# Git Workflow Cheatsheet

This guide shows the git commands for contributing to this repository.

```bash
Some Guidelines:
- Never push directly to main branch (!!!) 
- All your work will be done on a seperate branch 
###
#name your branches according to the features you are doing, not your own name, ideally each feature will have its own branch
#why? the code uploaded to github can be seen by anyone on the internet
###
- Push your features to your created branch 
- Then create a pull request (PR) to staging branch 
###
#the staging branch is an intermediate "main" branch JIC any fkups happen
###
- Always pull from staging before writing any new code to keep your local repo updated
- If you need any help, ask, I'll try my best to help
```

---

## Clone the Repository (first time only)
```bash
git clone git@github.com:ORG_NAME/REPO_NAME.git
cd REPO_NAME

git checkout main #switch to main branch
git pull origin main

git checkout -b [name_of_branch] # -b creates a new branch

##create your files and write your code in the new branch (DO NOT WRITE/PUSH TO MAIN)

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

## Subsequently,
## Before Pushing Any Commits, Pull from staging (IMPORTANT)
## Basically, always pull from staging branch before you write any code to prevent conflicts
```bash
git fetch origin
git checkout [name_of_branch]
git merge origin/main

# resolve conflicts if needed, write your code, then:

git add [file]
git commit
git push
```

---

## Other commands:
```bash
git branch # branch with * shows which branch you are in

```