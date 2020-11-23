#!/usr/bin/env python3

import argparse
from github import Github, GithubException
import json
import os
import re
import requests
import sys
from west.manifest import Manifest, ImportFlag

NOTE = "\n\n*Note: This comment is automatically posted and updated by the " \
       "Manifest GitHub Action.* "
 
_logging = 0

def log(s):
    if _logging:
        print(s, file=sys.stdout)

def die(s):
    print(s, file=sys.stderr)
    sys.exit(1)

def gh_tuple_split(s):
    sl = s.split('/')
    if len(sl) != 2:
        raise RuntimeError("Invalid org or dst format")

    return sl[0], sl[1]

def manifest_from_url(token, url):

    # Download manifest file
    header = {'Authorization': f'token {token}'}
    req = requests.get(url=url, headers=header)
    try:
        manifest = Manifest.from_data(req.content.decode(),
                                      import_flags=ImportFlag.IGNORE_PROJECTS)
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

    parser.add_argument('-m', '--messages', action='store',
                        required=False,
                        help='Messages to post.')

    parser.add_argument('-l', '--labels', action='store',
                        required=False,
                        help='Comma-separated list of labels.')

    parser.add_argument('--dnm-labels', action='store',
                        required=False,
                        help='Comma-separated list of labels.')

    parser.add_argument('--label-prefix', action='store',
                        required=False,
                        help='Label prefix.')

    parser.add_argument('-v', '--verbose-level', action='store',
                        type=int, default=0, choices=range(0, 2),
                        required=False, help='Verbosity level.')

    print(sys.argv)

    args = parser.parse_args()

    global _logging
    _logging = args.verbose_level

    messages = [x.strip() for x in args.messages.split('|')] \
               if args.messages != 'none' else None
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

    tk_usr = gh.get_user()
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

    try:
        old_mfile = gh_repo.get_contents(args.path, gh_pr.base.sha)
    except GithubException as e:
        print('Base revision does not contain a valid manifest')
        exit(0)

    new_manifest = manifest_from_url(token, new_mfile.raw_url)
    old_manifest = manifest_from_url(token, old_mfile.download_url)

    new_projs = set((p.name, p.revision) for p in new_manifest.projects)
    old_projs = set((p.name, p.revision) for p in old_manifest.projects)

    # List all existing projects that have changed revision, but not name.
    # If a project has changed name or is new, it is not handled for now.
    projs = set(filter(lambda p: p[0] in list(p[0] for p in old_projs),
                       new_projs - old_projs))
    if not len(projs):
        log('No projects updating revision')
        sys.exit(0)

    # Extract those that point to a PR
    re_rev = re.compile(r'pull\/(\d+)\/head')
    pr_projs = set(filter(lambda p: re_rev.match(p[1]), projs))
    log(f'PR projects: {pr_projs}')

    if not len(pr_projs):
        # Remove the DNM labels
        try:
            for l in dnm_labels:
                gh_pr.remove_from_labels(l)
        except GithubException as e:
            print('Unable to remove label')
    else:
        # Add the DNM labels
        for l in dnm_labels:
            gh_pr.add_to_labels(l)

    # Add the regular labels
    for l in labels:
        gh_pr.add_to_labels(l)

    # Link main PR to project PRs
    strs = list()
    strs.append('The following projects have a revision update in this Pull '
                'Request:\n')
    strs.append('| Name | Old Revision | New Revision | Project PR |')
    strs.append('| ---- | ------------ | ------------ | ---------- |')
    for p in projs:
        old_rev = list(filter(lambda _p: _p[0] == p[0], old_projs))[0][1]
        url = new_manifest.get_projects([p[0]])[0].url
        re_url = re.compile(r'https://github\.com/'
                             '([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)\/?')
        repo = gh.get_repo(re_url.match(url)[1])
        line = f'| {p[0]} | {old_rev} | {p[1]} '
        if p in pr_projs:
            pr = repo.get_pull(int(re_rev.match(p[1])[1]))
            line += f'| {pr.html_url} |'
        else:
            branches = list(map(lambda b: b.commit.sha,
                            filter(lambda b: p[1] == b.commit.sha,
                                   repo.get_branches())))
            line += f'({",".join(branches)})' if len(branches) else ''
            line += '| N/A |'


    comment = None
    for c in gh_pr.get_issue_comments():
        if c.user.login == tk_usr.login and NOTE in c.body:
            comment = c
            break

    message = '\n'.join(strs) + NOTE
    if not comment:
        print('Creating comment')
        gh_pr.create_issue_comment(message)
    else:
        print('Updating comment')
        comment.edit(message)


    log(f'Set new_projs: {new_projs}')
    log(f'Set old_projs: {old_projs}')
    log(f'Set difference: {new_projs - old_projs}')
    sys.exit(0)

if __name__ == '__main__':
    main()
