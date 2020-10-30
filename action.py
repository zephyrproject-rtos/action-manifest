#!/usr/bin/env python3

import argparse
from github import Github, GithubException
import json
import os
import sys

NOTE = "\n\n*Note: This comment is automatically posted and updated by the " \
       "Contribs GitHub Action.* "
 
def gh_tuple_split(s):
    sl = s.split('/')
    if len(sl) != 2:
        raise RuntimeError("Invalid org or dst format")

    return sl[0], sl[1]

def main():

    parser = argparse.ArgumentParser(
        description="GH Action script for contribution management",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-c', '--command', action='store',
                        choices=['external'],
                        required=True,
                        help='Command to execute.')

    parser.add_argument('-m', '--messages', action='store',
                        required=False,
                        help='Messages to post.')

    parser.add_argument('-l', '--labels', action='store',
                        required=False,
                        help='Comma-separated list of labels.')

    print(sys.argv)

    args = parser.parse_args()

    messages = [x.strip() for x in args.messages.split('|')]
    labels = [x.strip() for x in args.labels.split(',')]

    # Retrieve main env vars
    action = os.environ.get('GITHUB_ACTION', None)
    workflow = os.environ.get('GITHUB_WORKFLOW', None)
    org_repo = os.environ.get('GITHUB_REPOSITORY', None)

    print(f'Running action {action} from workflow {workflow} in {org_repo}')
    
    evt_name = os.environ.get('GITHUB_EVENT_NAME', None)
    evt_path = os.environ.get('GITHUB_EVENT_PATH', None)
    workspace = os.environ.get('GITHUB_WORKSPACE', None)

    print(f'Event {evt_name} in {evt_path} and workspace {workspace}')
 
    token = os.environ.get('GITHUB_TOKEN', None)
    if not token:
        sys.exit('Github token not set in environment, please set the '
                 'GITHUB_TOKEN environment variable and retry.')

    if not ("pull_request" in evt_name):
        sys.exit(f'Invalid event {evt_name}')

    with open(evt_path, 'r') as f:
        evt = json.load(f)

    pr = evt['pull_request']
    user = pr['user']
    login = user['login']

    print(f'user: {login} PR: {pr["title"]}')

    gh = Github(token)

    org, repo = gh_tuple_split(org_repo)

    print(f'org: {org} repo: {repo}')

    gh_org = gh.get_organization(org)
    gh_usr = gh.get_user(login)
    member = gh_org.has_in_members(gh_usr)
    nstr = '' if member else 'NOT '

    print(f'User {login} is {nstr}a member of org {org}')

    tk_usr = gh.get_user()
    gh_repo = gh.get_repo(org_repo)
    gh_pr = gh_repo.get_pull(int(pr['number']))

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

    if not member:
        print('Adding labels')
        for l in labels:
            gh_pr.add_to_labels(l)
    else:
        print('Removing labels')
        try:
            for l in labels:
                gh_pr.remove_from_labels(l)
        except GithubException as e:
            print('Unable to remove labels')

    sys.exit(0)

if __name__ == '__main__':
    main()
