#!/usr/bin/env python3
# Copyright (c) 2020 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0

# standard library imports only here
import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time

# 3rd party imports go here
import requests
from github import Github, GithubException
from west.manifest import Manifest, MalformedManifest, ImportFlag

NOTE = "\n\n*Note: This message is automatically posted and updated by the " \
       "Manifest GitHub Action.* "

_logging = 0


def log(s):
    if _logging:
        print(s, file=sys.stdout)


def die(s):
    print(f'ERROR: {s}', file=sys.stderr)
    sys.exit(1)


def gh_tuple_split(s):
    sl = s.split('/')
    if len(sl) != 2:
        raise RuntimeError("Invalid org or dst format")

    return sl[0], sl[1]


def cmd2str(cmd):
    # Formats the command-line arguments in the iterable 'cmd' into a string,
    # for error messages and the like

    return " ".join(shlex.quote(word) for word in cmd)

# Taken from Zephyr's check_compliance script


def git(*args, cwd=None):
    # Helper for running a Git command. Returns the rstrip()ed stdout output.
    # Called like git("diff"). Exits with SystemError (raised by sys.exit()) on
    # errors. 'cwd' is the working directory to use (default: current
    # directory).

    git_cmd = ("git",) + args
    try:
        git_process = subprocess.Popen(
            git_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
    except OSError as e:
        raise RuntimeError(f"failed to run '{cmd2str(git_cmd)}': {e}") from e

    stdout, stderr = git_process.communicate()
    stdout = stdout.decode("utf-8")
    stderr = stderr.decode("utf-8")
    if git_process.returncode or stderr:
        die(f"""\
'{cmd2str(git_cmd)}' exited with status {git_process.returncode} and/or wrote
to stderr.
==stdout==
{stdout}
==stderr==
{stderr}""")

    return stdout.rstrip()


def get_merge_base(pr, workspace, checkout):

    if checkout:
        cwd = os.path.join(workspace, checkout)
        log(f'Using git merge-base in {cwd}')
        sha = git('merge-base', pr.base.sha,  pr.head.sha, cwd=cwd)
        log(f'Found merge base {sha} with git')
        return sha

    base_commit = pr.base.repo.get_commit(pr.base.sha)
    head_commit = pr.head.repo.get_commit(pr.head.sha)
    # This is a very naive implementation but should work fine in general
    i = 10000
    base_shas = list()
    head_shas = list()
    start = time.time()
    while i:
        base_shas.append(base_commit.sha)
        head_shas.append(head_commit.sha)
        for s in head_shas:
            if s in base_shas:
                end = time.time()
                log(f'Found merge base {s} in {end - start:0.2f}s')
                return s
        base_parent = base_commit.parents
        head_parent = head_commit.parents
        if len(base_parent) != 1 or len(head_parent) != 1:
            die('Multiple parents detected in a commit')
        base_commit = base_parent[0]
        head_commit = head_parent[0]
        i = i - 1

    die('Unable to find a merge base')

# Taken from west:
# https://github.com/zephyrproject-rtos/west/blob/99482c684528cdf76a843e04b83c34e49a2d8cf2/src/west/app/project.py#L1165


def maybe_sha(rev):
    # Return true if and only if the given revision might be a SHA.

    try:
        int(rev, 16)
    except ValueError:
        return False

    return len(rev) <= 40


def fmt_rev(repo, rev):
    if not rev:
        return 'N/A'

    try:
        if maybe_sha(rev):
            branches = [b.name for b in repo.get_branches() if rev ==
                        b.commit.sha]
            s = repo.get_commit(rev).html_url
            # commits get formatted nicely by GitHub itself
            return s + f' ({",".join(branches)})' if len(branches) else s
        elif rev in [t.name for t in repo.get_tags()]:
            # For some reason there's no way of getting the URL via API
            s = f'{repo.html_url}/releases/tag/{rev}'
        elif rev in [b.name for b in repo.get_branches()]:
            # For some reason there's no way of getting the URL via API
            s = f'{repo.html_url}/tree/{rev}'
        else:
            return rev
    except GithubException:
        return rev

    return f'[{repo.full_name}@{rev}]({s})'

def shorten_rev(rev):
    if maybe_sha(rev):
        return rev[:8]
    return rev

def manifest_from_url(token, url):

    log(f'Creating manifest from {url}')

    # Download manifest file
    header = {'Authorization': f'token {token}'}
    req = requests.get(url=url, headers=header)
    try:
        manifest = Manifest.from_data(req.content.decode(),
                                      import_flags=ImportFlag.IGNORE)
    except MalformedManifest as e:
        die(f'Failed to parse manifest from {url}: {e}')

    return manifest


def main():

    parser = argparse.ArgumentParser(
        description="GH Action script for west manifest management",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-p', '--path', action='store',
                        required=True,
                        help='Path to the manifest file.')

    parser.add_argument('-m', '--message', action='store',
                        required=False,
                        help='Message to post.')

    parser.add_argument('--checkout-path', action='store',
                        required=False,
                        help='Path to the checked out PR.')

    parser.add_argument('-l', '--labels', action='store',
                        required=False,
                        help='Comma-separated list of labels.')

    parser.add_argument('--dnm-labels', action='store',
                        required=False,
                        help='Comma-separated list of labels.')

    parser.add_argument('--label-prefix', action='store',
                        required=False,
                        help='Label prefix.')

    parser.add_argument('--where', action='store',
                        choices=('comment', 'description'),
                        required=True, help='Where to post.')

    parser.add_argument('-v', '--verbose-level', action='store',
                        type=int, default=0, choices=range(0, 2),
                        required=False, help='Verbosity level.')

    print(sys.argv)

    args = parser.parse_args()

    global _logging
    _logging = args.verbose_level

    message = args.message if args.message != 'none' else None
    checkout = args.checkout_path if args.checkout_path != 'none' else None
    labels = [x.strip() for x in args.labels.split(',')] \
        if args.labels != 'none' else None
    dnm_labels = [x.strip() for x in args.dnm_labels.split(',')] \
        if args.dnm_labels != 'none' else None
    label_prefix = args.label_prefix if args.label_prefix != 'none' else None

    # Retrieve main env vars
    action = os.environ.get('GITHUB_ACTION', None)
    workflow = os.environ.get('GITHUB_WORKFLOW', None)
    org_repo = os.environ.get('GITHUB_REPOSITORY', None)

    log(f'Running action {action} from workflow {workflow} in {org_repo}')

    evt_name = os.environ.get('GITHUB_EVENT_NAME', None)
    evt_path = os.environ.get('GITHUB_EVENT_PATH', None)
    workspace = os.environ.get('GITHUB_WORKSPACE', None)

    log(f'Event {evt_name} in {evt_path} and workspace {workspace}')

    token = os.environ.get('GITHUB_TOKEN', None)
    if not token:
        sys.exit('Github token not set in environment, please set the '
                 'GITHUB_TOKEN environment variable and retry.')

    if not ("pull_request" in evt_name):
        sys.exit(f'Invalid event {evt_name}')

    with open(evt_path, 'r') as f:
        evt = json.load(f)

    pr = evt['pull_request']

    gh = Github(token)

    gh_repo = gh.get_repo(org_repo)
    gh_pr = gh_repo.get_pull(int(pr['number']))

    new_mfile = None
    for f in gh_pr.get_files():
        if f.filename == args.path:
            log(f'Matched manifest {f.filename}, url: {f.raw_url}')
            new_mfile = f
            break

    if not new_mfile:
        log('Manifest file {args.path} not modified by this Pull Request')
        sys.exit(0)

    base_sha = get_merge_base(gh_pr, workspace, checkout)
    log(f'PR base SHA: {gh_pr.base.sha} merge-base SHA: {base_sha}')

    try:
        old_mfile = gh_repo.get_contents(args.path, base_sha)
    except GithubException:
        print('Base revision does not contain a valid manifest')
        exit(0)

    old_manifest = manifest_from_url(token, old_mfile.download_url)
    new_manifest = manifest_from_url(token, new_mfile.raw_url)

    old_projs = set((p.name, p.revision) for p in old_manifest.projects)
    new_projs = set((p.name, p.revision) for p in new_manifest.projects)
    log(f'old_projs: {old_projs}')
    log(f'new_projs: {new_projs}')

    # Symmetric difference: everything that is not in both

    # Removed projects
    rprojs = set(filter(lambda p: p[0] not in list(p[0] for p in new_projs),
                        old_projs - new_projs))
    # Updated projects
    uprojs = set(filter(lambda p: p[0] in list(p[0] for p in old_projs),
                        new_projs - old_projs))
    # Added projects
    aprojs = new_projs - old_projs - uprojs

    # All projs
    projs = rprojs | uprojs | aprojs

    log(f'rprojs: {rprojs}')
    log(f'uprojs: {uprojs}')
    log(f'aprojs: {aprojs}')

    if not len(projs):
        log('No projects updated')
        sys.exit(0)

    # Extract those that point to a PR
    re_rev = re.compile(r'pull/(\d+)/head')
    # Revision cannot be a PR in a removed project
    pr_projs = set(filter(lambda p: re_rev.match(p[1]), uprojs | aprojs))
    log(f'PR projects: {pr_projs}')

    # Set labels
    if labels:
        for l in labels:
            gh_pr.add_to_labels(l)

    if label_prefix:
        for p in projs:
            gh_pr.add_to_labels(f'{label_prefix}{p[0]}')

    if dnm_labels:
        if not len(pr_projs):
            # Remove the DNM labels
            try:
                for l in dnm_labels:
                    gh_pr.remove_from_labels(l)
            except GithubException:
                print('Unable to remove label')
        else:
            # Add the DNM labels
            for l in dnm_labels:
                gh_pr.add_to_labels(l)

    # Link main PR to project PRs
    strs = list()
    if message:
        strs.append(message)
    strs.append('The following west manifest projects have been modified in this Pull '
                'Request:\n')
    strs.append('| Name | Old Revision | New Revision | Diff |')
    strs.append('| ---- | ------------ | ------------ |------|')
    # Sort in alphabetical order for the table
    for p in sorted(projs, key=lambda _p: _p[0]):
        log(f'Processing project {p[0]}')
        manifest = old_manifest if p in rprojs else new_manifest
        old_rev = None if p in aprojs else next(
            filter(lambda _p: _p[0] == p[0], old_projs))[1]
        new_rev = None if p in rprojs else p[1]
        url = manifest.get_projects([p[0]])[0].url
        re_url = re.compile(r'https://github\.com/'
                            '([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/?')
        try:
            repo = gh.get_repo(re_url.match(url)[1])
        except GithubException:
            print(f"Can't get repo for {p[0]}; output will be limited")
            strs.append(f'| {p[0]} | {old_rev} | {new_rev} | N/A |')
            continue

        line = f'| {p[0]} | {fmt_rev(repo, old_rev)} '
        if p in pr_projs:
            pr = repo.get_pull(int(re_rev.match(new_rev)[1]))
            line += f'| {pr.html_url} '
            line += f'| [{repo.full_name}#{pr.number}/files]' + \
                    f'({pr.html_url}/files) |'
        else:
            line += f'| {fmt_rev(repo, new_rev)} '
            if p in uprojs:
                line += f'| [{repo.full_name}@{shorten_rev(old_rev)}..' + \
                        f'{shorten_rev(new_rev)}]' + \
                        f'({repo.html_url}/compare/{old_rev}..{new_rev}) |'
            else:
                line += '| N/A |'

        strs.append(line)

    message = '\n'.join(strs) + NOTE
    if args.where == 'comment':
        comment = None
        for c in gh_pr.get_issue_comments():
            if NOTE in c.body:
                comment = c
                break

        if not comment:
            print('Creating comment')
            gh_pr.create_issue_comment(message)
        else:
            print('Updating comment')
            comment.edit(message)
    else:
        gh_pr.edit(body=gh_pr.body + '\n\n----\n\n' + message)

    sys.exit(0)


if __name__ == '__main__':
    main()
