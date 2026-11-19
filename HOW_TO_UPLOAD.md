# Upload this package to GitHub

1. Extract `6FLAS_GitHub_upload.zip` to a local directory.
2. Open your existing GitHub repository and choose **Add file > Upload files**.
3. Drag the CONTENTS of the extracted directory into the upload area, not an
   enclosing `github_upload` folder and not the ZIP itself.
4. Keep `README.md`, `requirements.txt`, `eval/`, `proto/`, `tools/`, `docs/`,
   and `results/` at the repository root. Include the hidden `.gitignore` file
   if your file picker displays it. No authentication token is included.
5. Use a message such as `Add revision evaluation code, tests and reproduction guide`.
6. After committing, confirm that the repository root displays the new README
   and source files. Uploading a ZIP alone does not unpack it into the repository.

These files update/add the matching paths. The web upload does not remove
unrelated old files already on GitHub. Review any old scripts/results separately
so readers do not confuse obsolete and current versions.

Keep `results/reference/` (historical aggregate) distinct from
`results/validation/` (new packaging verification). Do not replace the historical
paper numbers with fresh host timings. No manuscript, review letter, response,
cover letter, or private key is part of this upload.

After upload, optionally create a GitHub release/tag for the revision snapshot
and use its URL or commit ID in the manuscript response. A new project-wide
license has intentionally not been selected on the authors' behalf.
