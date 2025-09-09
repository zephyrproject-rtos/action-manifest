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
from dataclasses import dataclass
from pathlib import Path

# 3rd party imports go here
import requests
import yaml
from github import Github, GithubException
from github.File import File
from github.PullRequest import PullRequest
from github.Repository import Repository
from west.manifest import MANIFEST_PROJECT_INDEX, ImportFlag, MalformedManifest, Manifest

NOTE = "\n\n*Note: This message is automatically posted and updated by the " \
       "Manifest GitHub Action.* "

_logging = 0

@dataclass
class ProjectData:
    name: str | None = None
    old_rev: str | None = None
    new_rev: str | None = None
    repo: Repository | None = None
    pr: PullRequest | None = None
    files: list[File] | None = None
    myml: File | None = None
    rblobs: list[str] | None = None
    ublobs: list[str] | None= None
    ablobs: list[str] | None = None

def log(s):
    if _logging:
        print(s, file=sys.stdout)


def die(s):
    print(f'ERROR: {s}', file=sys.stderr)
    sys.exit(1)

def gh_pr_split(s):
    sl = s.split('/')
    if len(sl) != 3:
        raise RuntimeError(f"Invalid pr format: {s}")

    return sl[0], sl[1], sl[2]

def cmd2str(cmd):
    # Formats the command-line arguments in the iterable 'cmd' into a string,
    # for error messages and the like

    return " ".join(shlex.quote(word) for word in cmd)

def str2import_flag(import_flag):
    flags = {'all': ImportFlag.DEFAULT, 'none': ImportFlag.IGNORE,
             'self': ImportFlag.IGNORE_PROJECTS}
    return flags[import_flag]

# Taken from Zephyr's check_compliance script
def git(*args, cwd=None):
    # Helper for running a Git command. Returns the rstrip()ed stdout output.
    # Called like git("diff"). Exits with SystemError (raised by sys.exit()) on
    # errors. 'cwd' is the working directory to use (default: current
    # directory).

    git_cmd = ("git",) + args
    log(f'Executing git cmd {git_cmd}')
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


def get_merge_base(pr, checkout):

    if checkout:
        log(f'Using git merge-base in {checkout}')
        sha = git('merge-base', pr.base.sha,  pr.head.sha, cwd=checkout)
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

# Inspired in west code:
# https://github.com/zephyrproject-rtos/west/blob/99482c684528cdf76a843e04b83c34e49a2d8cf2/src/west/app/project.py#L1165
def is_sha(rev):
    # Return true if and only if the given revision might be a full 40-byte SHA.
    try:
        int(rev, 16)
    except ValueError:
        return False

    return len(rev) == 40

# Returns tuple (valid_rev, is_impostor)
def is_valid_rev(repo, rev, check_impostor):

    # No revision to check, consider everything OK
    if not rev:
        log('is_valid_rev: rev is None')
        return (True, False)
    sha = is_sha(rev)

    # Verify that the commit actually exists, regardless of whether it's an
    # impostor or not
    if sha:
        try:
            repo.get_commit(rev)
        except GithubException:
            return (False, False)
        # If no additional checks needed, return
        if not check_impostor:
            return (True, False)

    def compare(base, head):
        try:
            c = repo.compare(base, head)
        except GithubException as e:
            if (e.status == 404 and
               "no common ancestor" in e.data["message"].lower()):
                   log(f"No common ancestor between {base} and {head}")
                   return False
            else:
                log(f'is_valid_rev: compare: GithubException: {e}')
                raise
        status_ok = ('behind', 'identical') if sha else ('identical')
        return c.status in status_ok

    try:
        for b in repo.get_branches():
            if compare(f'refs/heads/{b.name}', rev):
                log(f'is_valid_rev: Found revision {rev} in branch {b.name}')
                return (True, False)
        for t in repo.get_tags():
            if compare(f'refs/tags/{t.name}', rev):
                log(f'is_valid_rev: Found revision {rev} in tag {t.name}')
                return (True, False)
    except GithubException as e:
        log(f'is_valid_rev: GithubException: {e}')
        return (False, False)

    return (True, True) if sha else (False, False)

def fmt_rev(repo, rev):
    if not rev:
        return 'N/A'

    try:
        if is_sha(rev):
            all_refs = [b for b in repo.get_branches()] + \
                       [t for t in repo.get_tags()]
            refs = [f'`{r.name}`' for r in all_refs if rev == r.commit.sha]
            s = repo.get_commit(rev).html_url
            # commits get formatted nicely by GitHub itself
            return s + f' ({",".join(refs)})' if len(refs) else s
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
    if is_sha(rev):
        return rev[:8]
    return rev

def request(token, url):
    header = {'Authorization': f'token {token}'}
    req = requests.get(url=url, headers=header)
    return req

def yaml_from_url(token, url):

    log(f'Creating yaml from {url}')

    # Download yaml file
    raw_yaml = request(token, url).content.decode()
    try:
        yml = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as e:
        log(f'Failed to parse module.yml from {url}: {e}')
        return None

    return yml

def manifest_from_url(token, url):

    log(f'Creating manifest from {url}')

    # Download manifest file
    raw_manifest = request(token, url).content.decode()
    log('Manifest.from_data()')
    try:
        manifest = Manifest.from_data(raw_manifest,
                                      import_flags=ImportFlag.IGNORE)
    except MalformedManifest as e:
        die(f'Failed to parse manifest from {url}: {e}')

    log(f'Created manifest {manifest}')
    return manifest

def _file_to_download_url(token, file):
        # When authorization is enabled we require a
        # raw.githubusercontent.com/..?token= style URL (aka download_url) but
        # new_mfile.raw_url gives us a <repo>/raw/<sha> style URL
        cont = request(token, url=file.contents_url).content.decode()
        return json.loads(cont)['download_url']

def _get_manifests_from_gh(token, gh_repo, mpath, new_mfile, base_sha):

    try:
        old_mfile = gh_repo.get_contents(mpath, base_sha)
    except GithubException:
        log('Base revision does not contain a valid manifest')
        exit(0)

    old_manifest = manifest_from_url(token, old_mfile.download_url)

    if new_mfile:
        new_mfile_durl = _file_to_download_url(token, new_mfile)
        new_manifest = manifest_from_url(token, new_mfile_durl)
    else:
        # No change in manifest, run the checks anyway on the same manifest
        new_manifest = old_manifest

    return (old_manifest, new_manifest)

def _get_manifests_from_tree(mpath, gh_pr, checkout, base_sha, import_flag):
    # Check if current tree is at the right location

    mfile = (Path(checkout) / Path(mpath)).resolve()

    def manifest_at_rev(sha):
        cur_sha = git('rev-parse', 'HEAD', cwd=checkout)
        if cur_sha != sha:
            # Use --quiet to avoid Git writing a warning about a commit left
            # behind in stderr
            git('checkout', '--quiet', '--detach', sha, cwd=checkout)
        return Manifest.from_file(mfile, import_flags=import_flag)

    old_manifest = manifest_at_rev(base_sha)
    new_manifest = manifest_at_rev(gh_pr.head.sha)

    return (old_manifest, new_manifest)

def _get_merge_status(len_a, len_r, len_pr, len_meta, blob_changes, impostor_shas,
                      invalid_revs, unreachables):
    strs = []
    def plural(count):
        return 's' if count > 1 else ''

    if len_a:
        strs.append(f'{len_a} added project{plural(len_a)}')
    if len_r:
        strs.append(f'{len_r} removed project{plural(len_r)}')
    if len_pr:
        strs.append(f'{len_pr} project{plural(len_pr)} with PR revision')
    if len_meta:
        strs.append(f'{len_meta} project{plural(len_meta)} with metadata changes')
    if blob_changes:
        strs.append(f'{blob_changes} blob change{plural(blob_changes)}')
    if impostor_shas:
        strs.append(f'{impostor_shas} impostor SHA{plural(impostor_shas)}')
    if invalid_revs:
        strs.append(f'{invalid_revs} nonexistent revision{plural(impostor_shas)}')
    if unreachables:
        strs.append(f'{unreachables} unreachable repo{plural(unreachables)}')

    if not len(strs):
        return False, '\u2705 **All manifest checks OK**'

    n = '\U000026D4 **DNM label due to: '
    for i, s in enumerate(strs):
        if i == (len(strs) - 1):
            _s = f'and {s}' if len(strs) > 1 else s
        else:
            _s = f'{s}, ' if (len(strs) - i > 2) else f'{s} '
        n += _s
    n += '**'
    return True, n

def _get_sets(old_items, new_items, log_items=True):

    # Removed items
    ritems = set(filter(lambda p: p[0] not in list(p[0] for p in new_items),
                        old_items - new_items))
    # Updated items
    uitems = set(filter(lambda p: p[0] in list(p[0] for p in old_items),
                        new_items - old_items))
    # Added items
    aitems = new_items - old_items - uitems

    # All items
    items = ritems | uitems | aitems

    if log_items:
        log(f'ritems: {ritems}')
        log(f'uitems: {uitems}')
        log(f'aitems: {aitems}')

    return (items, ritems, uitems, aitems)


def main():

    parser = argparse.ArgumentParser(
        description="GH Action script for west manifest management",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-p', '--path', action='store',
                        required=True,
                        help='Path to the manifest file.')

    parser.add_argument('--pr', default=None, required=True,
                        help='<org>/<repo>/<pr num>')

    parser.add_argument('-m', '--message', action='store',
                        required=False,
                        help='Message to post.')

    parser.add_argument('--checkout-path', action='store',
                        required=False,
                        help='Path to the checked out PR.')

    parser.add_argument('--use-tree-checkout', action='store',
                        required=False,
                        help='Use a checked-out tree to parse the manifests.')

    parser.add_argument('--west-import-flag', action='store',
                        required=False, choices=['all', 'none', 'self'],
                        help='Use a checked-out tree to parse the manifests.')

    parser.add_argument('--check-impostor-commits', action='store',
                        required=False,
                        help='Check for impostor commits.')

    parser.add_argument('--allowed-unreachables', action='store',
                        required=False,
                        help='Comma-separated list of repos which are allowed to be unreachable.')

    parser.add_argument('-l', '--labels', action='store',
                        required=False,
                        help='Comma-separated list of labels.')

    parser.add_argument('--dnm-labels', action='store',
                        required=False,
                        help='Comma-separated list of labels.')

    parser.add_argument('--blobs-added-labels', action='store',
                        required=False,
                        help='Comma-separated list of labels.')

    parser.add_argument('--blobs-modified-labels', action='store',
                        required=False,
                        help='Comma-separated list of labels.')

    parser.add_argument('--label-prefix', action='store',
                        required=False,
                        help='Label prefix.')

    parser.add_argument('-v', '--verbose-level', action='store',
                        type=int, default=0, choices=range(0, 2),
                        required=False, help='Verbosity level.')

    log(sys.argv)

    args = parser.parse_args()

    global _logging
    _logging = args.verbose_level

    message = args.message if args.message != 'none' else None
    checkout = args.checkout_path if args.checkout_path != 'none' else None
    import_flag = str2import_flag(args.west_import_flag or 'all')
    use_tree = args.use_tree_checkout != 'false'
    check_impostor = args.check_impostor_commits != 'false'
    allowed_unreachables = [x.strip() for x in args.allowed_unreachables.split(',')] \
        if args.allowed_unreachables != 'none' else []
    labels = [x.strip() for x in args.labels.split(',')] \
        if args.labels != 'none' else None
    dnm_labels = [x.strip() for x in args.dnm_labels.split(',')] \
        if args.dnm_labels != 'none' else None
    bloba_labels = [x.strip() for x in args.blobs_added_labels.split(',')] \
        if args.blobs_added_labels != 'none' else None
    blobm_labels = [x.strip() for x in args.blobs_modified_labels.split(',')] \
        if args.blobs_modified_labels != 'none' else None
    label_prefix = args.label_prefix if args.label_prefix != 'none' else None

    if use_tree and not checkout:
        sys.exit("Cannot use a tree checkout without a checkout path")

    # Abs path to checked-out tree
    workspace = os.environ.get('GITHUB_WORKSPACE', None)

    token = os.environ.get('GITHUB_TOKEN', None)
    if not token:
        sys.exit('Github token not set in environment, please set the '
                 'GITHUB_TOKEN environment variable and retry.')

    gh = Github(token)

    org_str, repo_str, pr_str = gh_pr_split(args.pr)
    gh_repo = gh.get_repo(f'{org_str}/{repo_str}')
    gh_pr = gh_repo.get_pull(int(pr_str))

    log(f'pr user: {gh_pr.head.user} and repo: {gh_pr.head.repo}')
    mpath = args.path
    new_mfile = None
    for f in gh_pr.get_files():
        if f.filename == args.path:
            log(f'Matched manifest {f.filename}, url: {f.raw_url}')
            new_mfile = f
            break

    if not new_mfile:
        log(f'Manifest file {args.path} not modified by this Pull Request')

    if checkout:
        checkout = ((Path(workspace) / Path(checkout)).resolve() if workspace else
                   Path(checkout).resolve())
        if not checkout.is_dir():
            die(f'checkout repo {checkout} does not exist; check path')

        log(git('log', '--oneline', '-n', '5', cwd=checkout))
        log(git('remote', '-v', cwd=checkout))

        org_sha = git('rev-parse', 'HEAD', cwd=checkout)
        log(f'Checkout path: {checkout}, original sha: {org_sha}')
        # Fetch from the PR to actually get the PR HEAD commit (pr.head.sha)
        git('fetch', '-q', gh_repo.clone_url, f'pull/{pr_str}/head', cwd=checkout)

    base_sha = get_merge_base(gh_pr, checkout)
    log(f'PR base SHA: {gh_pr.base.sha} merge-base SHA: {base_sha}')

    if use_tree:
        (old_manifest, new_manifest) = _get_manifests_from_tree(mpath,
                                                                gh_pr, checkout,
                                                                base_sha,
                                                                import_flag)
    else:
        (old_manifest, new_manifest) = _get_manifests_from_gh(token, gh_repo,
                                                              mpath, new_mfile,
                                                              base_sha)
    if checkout:
        # Leave the tree in the exact state it was received
        git('checkout', '--quiet', '--detach', org_sha, cwd=checkout)

    # Ensure we only remove the manifest project
    assert(MANIFEST_PROJECT_INDEX == 0)
    ops = old_manifest.projects[MANIFEST_PROJECT_INDEX + 1:]
    nps = new_manifest.projects[MANIFEST_PROJECT_INDEX + 1:]

    old_projs = set((p.name, p.revision) for p in ops)
    new_projs = set((p.name, p.revision) for p in nps)

    log(f'old_projs: {old_projs}')
    log(f'new_projs: {new_projs}')

    log('Revision sets')
    (projs, rprojs, uprojs, aprojs) = _get_sets(old_projs, new_projs)

    projs_names = [name for name, rev in projs]

    if not len(projs):
        log('No projects updated')

    # Extract those that point to a PR
    re_rev = re.compile(r'(?:refs/)?pull/(\d+)/head')
    # Revision cannot be a PR in a removed project
    pr_projs = set(filter(lambda p: re_rev.match(p[1]), uprojs | aprojs))
    log(f'PR projects: {pr_projs}')

    log(f'projs_names: {str(projs_names)}')

    impostor_shas = 0
    invalid_revs = 0
    unreachables = 0
    projdata = dict()
    # Link main PR to project PRs
    strs = list()
    if message:
        strs.append(message)
    strs.append('The following west manifest projects have changed revision in this Pull '
                'Request:\n')
    strs.append('| Name | Old Revision | New Revision | Diff |')
    strs.append('| ---- | ------------ | ------------ |------|')
    # Sort in alphabetical order for the table
    for p in sorted(projs, key=lambda _p: _p[0]):
        pdata = ProjectData(name=p[0])
        projdata[p[0]] = pdata
        log(f'Processing project {p[0]}')
        manifest = old_manifest if p in rprojs else new_manifest
        old_rev = None if p in aprojs else next(
            filter(lambda _p: _p[0] == p[0], old_projs))[1]
        new_rev = None if p in rprojs else p[1]
        # Store revisions for later use
        pdata.old_rev = old_rev
        pdata.new_rev = new_rev
        or_note = ' (Added)' if not old_rev else ''
        nr_note = ' (Removed)' if not new_rev else ''
        name_note = ' \U0001F195' if not old_rev else ' \U0000274c ' if \
                    not new_rev else ''
        url = manifest.get_projects([p[0]])[0].url
        re_url = re.compile(r'https://github\.com/'
                            '([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/?')
        try:
            repo = gh.get_repo(re_url.match(url)[1])
        except (GithubException, TypeError) as error:
            log(error)
            log(f"Can't get repo for {p[0]}; output will be limited")
            strs.append(f'| {p[0]}{name_note} | {old_rev}{or_note} | {new_rev}{nr_note} | N/A |')

            if p[0] not in allowed_unreachables:
                unreachables += 1
            log(f'{p[0]}: {pdata}')
            continue

        pdata.repo = repo
        line = f'| {p[0]}{name_note} | {fmt_rev(repo, old_rev)}{or_note} '
        if p in pr_projs:
            pr = repo.get_pull(int(re_rev.match(new_rev)[1]))
            line += f'| {pr.html_url}{nr_note} '
            line += f'| [{repo.full_name}#{pr.number}/files]' + \
                    f'({pr.html_url}/files) |'
            pdata.pr = pr
            # Store files changed
            pdata.files = [f for f in pr.get_files()]
        else:
            (valid_rev, impostor) = is_valid_rev(repo, new_rev, check_impostor)
            if impostor:
                impostor_shas += 1
                line += f'|\u274c Impostor SHA: {fmt_rev(repo, new_rev)}{nr_note} '
            elif not valid_rev:
                invalid_revs += 1
                line += f'|\u274c Nonexistent revision: {fmt_rev(repo, new_rev)}{nr_note}'
            else:
                line += f'| {fmt_rev(repo, new_rev)}{nr_note}'
            if p in uprojs:
                line += f'| [{repo.full_name}@{shorten_rev(old_rev)}..' + \
                        f'{shorten_rev(new_rev)}]' + \
                        f'({repo.html_url}/compare/{old_rev}..{new_rev}) |'
                # Store files changed
                try:
                    c = repo.compare(old_rev, new_rev)
                    pdata.files = [f for f in c.files]
                except GithubException as e:
                    log(e)
                    log(f"Can't get files changed for {p[0]}")
            else:
                line += '| N/A |'

        log(f'{p[0]}: {pdata}')
        strs.append(line)

    def _hashable(o):
        if isinstance(o, list):
            return frozenset(o)
        return o

    def _cmp_module_yml(name):
        if name not in projdata:
            return None

        p = projdata[name]

        if not p.repo or not p.myml or not p.old_rev or not p.new_rev:
            return None

        try:
            old_url = p.repo.get_contents(p.myml.filename, p.old_rev).download_url
            if not p.pr:
                new_url = p.repo.get_contents(p.myml.filename, p.new_rev).download_url
            else:
                new_url = _file_to_download_url(token, p.myml)
        except GithubException:
            log('Unable to fetch module.yml file')
            return None

        old_myml = yaml_from_url(token, old_url)
        new_myml = yaml_from_url(token, new_url)

        # Sort them to ensure moving them around has no effect, and then convert
        # them to sets to be able to operate on those. Tuples are hashable,
        # dictionaries are not
        try:
            # Save the path tuple first, then the rest of the dict
            old_blobs = set(
                tuple([('path', d.pop('path'))] + sorted(d.items(), key=lambda m: m[0]))
                for d in old_myml['blobs']
            )
        except KeyError:
            log(f'No old blobs found in this module.yml: {name}')
            old_blobs = set()

        try:
            # Save the path tuple first, then the rest of the dict
            new_blobs = set(
                tuple([('path', d.pop('path'))] + sorted(d.items(), key=lambda m: m[0]))
                for d in new_myml['blobs']
            )
        except KeyError:
            log(f'No new blobs found in this module.yml: {name}')
            new_blobs = set()


        log(f'{name}: old blobs #{len(old_blobs)}')
        log(f'{name}: new blobs #{len(new_blobs)}')

        log('Blobs sets')
        (_, rblobs, ublobs, ablobs) = _get_sets(old_blobs, new_blobs)

        # Populate the project data with the results as a list of paths
        p.rblobs = [d['path'] for d in (dict((k, v) for k, v in b) for b in rblobs)]
        p.ublobs = [d['path'] for d in (dict((k, v) for k, v in b) for b in ublobs)]
        p.ablobs = [d['path'] for d in (dict((k, v) for k, v in b) for b in ablobs)]

        log(f'p.rblobs: {p.rblobs}')
        log(f'p.ublobs: {p.ublobs}')
        log(f'p.ablobs: {p.ablobs}')

        return (p.rblobs, p.ublobs, p.ablobs)

    def _module_changed(p):
        if p.name in projdata and projdata[p.name].files:
            for f in projdata[p.name].files:
                if ('zephyr/module.yml' in f.filename or
                   'zephyr/module.yaml' in f.filename):
                    projdata[p.name].myml = f
                    log(f'project {p.name} modifies module.yml')
                    return True
        return False

    # Check additional metadata
    meta_op = set((p.name, p.url, _hashable(p.submodules),
                   _hashable(p.west_commands), False) for p in ops)
    meta_np = set((p.name, p.url, _hashable(p.submodules),
                   _hashable(p.west_commands), _module_changed(p)) for p in nps)

    log('Metadata sets')
    (_, _, meta_uprojs, meta_aprojs) = _get_sets(meta_op, meta_np)

    def _cmp_old_new(p, index, force_change=False):
        old = None if p in meta_aprojs else next(filter(lambda _p: _p[0] == p[0], meta_op))[index]
        new = next(filter(lambda _p: _p[0] == p[0], meta_np))[index]
        log(f'name: {p[0]} index: {index} old: {old} new: {new}')
        # Special handling for an added project
        if old is None and not new:
            return ''
        # Select which symbol to show
        if not old and new:
            return '\U0001F195' if not force_change else '\u270f' # added
        elif not new and old:
            return '\u274c' # removed
        elif new != old:
            return '\u270f' # modified
        else:
            return ''

    # Store blob stats
    blobs_removed = 0
    blobs_modified = 0
    blobs_added = 0

    if len(meta_uprojs):
        strs.append('\n\nAdditional metadata changed:\n')
        strs.append('| Name | URL | Submodules | West cmds | `module.yml` | Blobs |')
        strs.append('| ---- | --- | ---------- | --------- | ------------ | ----- |')
        for p in sorted(meta_uprojs, key=lambda _p: _p[0]):
            url = _cmp_old_new(p, 1)
            subms = _cmp_old_new(p, 2)
            wcmds = _cmp_old_new(p, 3)
            mys = _cmp_old_new(p, 4, True)
            blobs = ''
            if mys:
                (rblobs, ublobs, ablobs) = _cmp_module_yml(p[0])
                blobs_removed += len(rblobs)
                blobs_modified += len(ublobs)
                blobs_added += len(ablobs)
                items = 3 - (rblobs, ublobs, ablobs).count([])
                def _get_blob_str(b, sym):
                    nonlocal items
                    s = ''
                    if b:
                        s += f'{len(b)}x {sym}'
                        items -= 1
                        s += ", " if items else ''
                    return s

                blobs += _get_blob_str(rblobs, '\u274c')
                blobs += _get_blob_str(ublobs, '\u270f')
                blobs += _get_blob_str(ablobs, '\U0001F195')

            line = f'| {p[0]} | {url} | {subms} | {wcmds} | {mys} | {blobs} |'
            strs.append(line)

    # Add a note about the merge status of the manifest PR
    dnm, status_note = _get_merge_status(len(aprojs), len(rprojs), len(pr_projs),
                                         len(meta_uprojs), blobs_removed +
                                         blobs_modified + blobs_added, impostor_shas,
                                         invalid_revs, unreachables)
    status_note = f'\n\n{status_note}'

    message = '\n'.join(strs) + status_note + NOTE
    comment = None
    for c in gh_pr.get_issue_comments():
        if NOTE in c.body:
            comment = c
            break

    if not comment:
        if len(projs):
            log('Creating comment')
            comment = gh_pr.create_issue_comment(message)
        else:
            log('Skipping comment creation, no manifest changes')
    else:
        log('Updating comment')
        comment.edit(message)

    if not comment:
        log('PR not modifying or having modified west projects, exiting early')
        sys.exit(0)

    # Now onto labels
    log(f"labels: {str(labels)}")

    # Parse a list of labels given as '--labels ...' and
    # return the ones that should be added to the PR.
    def get_relevant_labels(label_list):
        def get_modules(lbl):
            return map(str.strip, lbl.split(':')[1].split(';'))
        def is_relevant(lbl):
            return len(set(get_modules(lbl)).intersection(projs_names)) != 0

        return [
            lbl.split(':')[0].strip() for lbl in label_list if ':' not in lbl or is_relevant(lbl)
        ]

    # Set or unset labels
    if labels:
        for lbl in get_relevant_labels(labels):
            if len(projs):
                log(f'Adding label {lbl}')
                try:
                    gh_pr.add_to_labels(lbl)
                except GithubException:
                    log(f'Failed to add label "{lbl}". It might not exist in the repo.')
            else:
                try:
                    log(f'Removing label {lbl}')
                    gh_pr.remove_from_labels(lbl)
                except GithubException:
                    log(f'Unable to remove label {lbl}')

    if label_prefix:
        for p in projs:
            lbl = f'{label_prefix}{p[0]}'
            log(f'Adding label {lbl}')
            try:
                gh_pr.add_to_labels(lbl)
            except GithubException:
                log(f'Failed to add label "{lbl}". It might not exist in the repo.')
        if not len(projs):
            for lbl in gh_pr.get_labels():
                if lbl.name.startswith(label_prefix):
                    # Remove existing label
                    try:
                        log(f'Removing label {lbl}')
                        gh_pr.remove_from_labels(lbl)
                    except GithubException:
                        log(f'Unable to remove prefixed label {lbl}')

    def _update_labels(labels, condition):
        if labels:
            if not condition:
                # Remove the labels
                try:
                    for lbl in labels:
                        log(f'Removing label {lbl}')
                        gh_pr.remove_from_labels(lbl)
                except GithubException:
                    log('Unable to remove label')
            else:
                # Add the labels
                for lbl in labels:
                    log(f'Adding label {lbl}')
                    try:
                        gh_pr.add_to_labels(lbl)
                    except GithubException:
                        log(f'Failed to add label "{lbl}". It might not exist in the repo.')


    _update_labels(dnm_labels, dnm)
    _update_labels(blobm_labels, blobs_modified)
    _update_labels(bloba_labels, blobs_added)

    sys.exit(0)


if __name__ == '__main__':
    main()
