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
- Then create a pull request to staging branch 
###
#the staging branch is an intermediate "main" branch JIC any fkups happen
###
- Always pull from staging before writing any new code to keep your local repo updated
- If you need any help, ask, I'll try my best to help
```

---

## After Cloning the Repository 
```bash
cd [repo_name]

git checkout staging #switch to staging branch
git pull origin staging

git checkout -b [name_of_branch] # -b creates a new branch
##create your files and write your code in the new branch (DO NOT WRITE/PUSH TO MAIN)
```
---

## Commiting and Pushing your Code
```bash
git add . # . adds all files. use the file name directly if you wish to only commit specific files 

git commit -m "[short_discription_of_commit]" # discriptions must be easy for others to understand

git push -u origin [name_of_branch] # push your local repo to the specified branch in github
```

---

## Open a Pull Request (PR)
```bash
Go to the repository on GitHub.

GitHub will show a banner: “Compare & pull request” → click it.

Fill in the PR template:

Title: short summary (e.g. feat: add .eml upload form)

Description: what you changed + how to test 

Submit the PR (target branch = staging).
```

---


## Subsequently, Before Pushing Any Commits or working on any code, Pull from staging first (IMPORTANT) 
```bash
git pull origin staging

# resolve conflicts if any

# write your code

# same commands to push your files
git add .
git commit -m "[message]"
git push -u origin [your_branch]
```
---

## Other commands:
```bash
git branch # branch with * shows which branch you are in
use q to quit
```