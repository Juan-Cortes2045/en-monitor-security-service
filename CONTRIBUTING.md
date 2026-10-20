# Contributing

Thanks for contributing to `security-service`. Before touching any code, please read the project's Git workflow and commit conventions:

📄 **[Git Conventions](https://github.com/code-sena/en-monitor-docs/blob/main/00-governance/git-conventions.md)**

That document covers everything you need before your first commit:

- Branch strategy (`main` / `dev` / `feat` / `fix` / `chore` / `hotfix`)
- Branch naming format
- Commit message format (Conventional Commits)
- Pull Request policy (size limit, reviewers, review time)
- Merge policy (Squash vs. Merge Commit)
- Tagging and versioning (SemVer)

## Quick checklist before opening a PR

- [ ] Branch created from `dev`, named `type/description-in-kebab-case`
- [ ] One branch = one task (no mixed features)
- [ ] Commits follow Conventional Commits format
- [ ] PR is under 400 lines of code (excluding tests) — split it if larger
- [ ] Architecture rules in [`docs/Architecture.md`](docs/Architecture.md) were followed
- [ ] At least 1 reviewer approval obtained
- [ ] CI checks are green

If anything here is unclear, ask before merging — not after.