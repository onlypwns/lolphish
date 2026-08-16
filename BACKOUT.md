# Backout plan — batch 1 (v0.5)

If the v0.5 changes are not satisfactory, restore the previous state using the
pre-existing backup branch.

## Option A: restore the backup branch (recommended)

```bash
git fetch origin
git checkout main
git reset --hard backup-before-batch-1
git push origin main --force-with-lease
```

This reverts `main` to commit `56d1c89` (the v0.4 redesign).

## Option B: revert the v0.5 commit

```bash
git checkout main
git revert 37c7368
# keep the default revert commit message, save, and exit the editor
git push origin main
```

This keeps the v0.5 history but applies an inverse commit on top.

## What is preserved

The backup branch `backup-before-batch-1` points to `56d1c89` and is already
pushed to origin, so it will survive even if this file is deleted.

## Cleanup

Once you are happy with v0.5, delete this file and the backup branch:

```bash
rm BACKOUT.md
git add BACKOUT.md
git commit -m "chore: remove batch-1 backout plan"
git push origin main
git push origin --delete backup-before-batch-1
```
