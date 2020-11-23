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

    _logging = args.verbose_level

    messages = [x.strip() for x in args.messages.split('|')] \
               if args.messages != 'none' else None
    labels = [x.strip() for x in args.labels.split(',')] \
             if args.labels != 'none' else None
    dnm_labels = [x.strip() for x in args.dnm_labels.split(',')] \
             if args.dnm_labels != 'none' else None
    lp = args.lp if args.lp != 'none' else None

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
    # Extract those that point to a PR
    re_rev = re.compile(r'pull\/(\d+)\/head')
    pr_projs = set(filter(lambda p: re_rev.match(p[1]), projs))
    log(f'PR projects: {pr_projs}')

    if not len(pr_projs):
        # Remove the DNM label
        try:
            gh_pr.remove_from_labels(labels[0])
        except GithubException as e:
            print('Unable to remove label')
    else:
        # Add the DNM label
        gh_pr.add_to_labels(labels[0])

    # Link main PR to project PRs
    prs = list()
    for p in pr_projs:
        url = new_manifest.get_projects([p[0]])[0].url
        re_url = re.compile(r'https://github\.com/'
                             '([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)\/?')
        repo = gh.get_repo(re_url.match(url)[1])
        pr = repo.get_pull(int(re_rev.match(p[1])[1]))
        prs.append((p, pr))
        pr_url = pr.html_url

    for pr in prs:
        print(f'Processing pr {pr}')
    sys.exit(0)

    comment = None
    for c in gh_pr.get_issue_comments():
        if c.user.login == tk_usr.login and NOTE in c.body:
            comment = c
            break

    message = messages[0] + NOTE
    if not comment and not member:
        print('Creating comment')
        gh_pr.create_issue_comment(message)
    elif comment and member and len(messages) > 1:
        print('Updating comment')
        comment.edit(messages[1] + NOTE)



    log(f'Set new_projs: {new_projs}')
    log(f'Set old_projs: {old_projs}')
    log(f'Set difference: {new_projs - old_projs}')
    sys.exit(0)

    if len(projects) == 0:
        log('No projects using a pull request as a revision')
        sys.exit(0)

    for p in projects:
        print(re_rev.match(p.revision).group(1))
        print(p)

    sys.exit(0)

    gh_org = gh.get_organization(org)
    gh_usr = gh.get_user(login)

    tk_usr = gh.get_user()
    gh_repo = gh.get_repo(org_repo)

    comment = None
    for c in gh_pr.get_issue_comments():
        if c.user.login == tk_usr.login and NOTE in c.body:
            comment = c
            break

    message = messages[0] + NOTE
    gh_pr.create_issue_comment(message)
    comment.edit(messages[1] + NOTE)

    for l in labels:
        gh_pr.add_to_labels(l)
    try:
        for l in labels:
            gh_pr.remove_from_labels(l)
    except GithubException as e:
        print('Unable to remove labels')

    sys.exit(0)

if __name__ == '__main__':
    main()
