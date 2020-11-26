# action-manifest

This respository contains a GitHub action implemented in Python to partially
automate [west](https://docs.zephyrproject.org/latest/guides/west/index.html)-based
manifest workflows.

It currently performs the following tasks:

- Parses the PR changes to detect if the manifest file has been modified
- Constructs both the old manifest (the one in the PR base SHA) and the new
  manifest (the one in the tip of the PR) and compares them
- Adds a set of DNM labels when one or more of the `revision:` fields in the
  manifest point to a Pull Request
- Adds a set of labels to be associated with a change to the manifest
- Adds a set of per-manifest project with the format `{prefix}{project_name}`
- Posts and updates a message with a revision comparison table

See [action.yml](action.yml) for a full list of options.
