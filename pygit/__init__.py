import os
from argparse import ArgumentParser
from sys import exit
from typing import Dict, Any, List, Union, Optional
import requests
import pprint

""" GitLab API Python Client

    A lightweight Git client written in Python that can check branch structure on a repo, create branches if needed and
    setup and configure Webhooks.

    In order to be able to read and write to repo, you must first create a Personal Access Token and specify it with 
    either --token or set the GITLAB_TOKEN environment variable. The account that is used to create this PAT must have 
    the proper permissions on the repo. Because this client will need write permissions to modify the repo a deploy 
    key will not work. 

    The minimum requirements for running this script are:
        - --token or GITLAB_TOKEN environment variable
        - -pid (--project id)
           OR -p (--project)


Example:

    Basic usage:

    $ ./pygit.py -pid 186
        or
    $ ./pygit.py --project brandi-flaskql

    Setup Webhook(s) for project:
    
    $ ./pygit.py --project brandi-flaskql --debug true --branches master release

Attributes:
    base_url (str): The URL of the GitLab server.
    token (str): The token used to authenticate with GitLab.
    project_id (str): The ID of the project.
    project_name (str): The name of the project.
    protected_branches (List[str]): The list of protected branches (for AgileDagger).
    branches (List[str]): List of branch names to configure webhook(s) for.
    create_branches (bool): Whether or not to create branches if they do not exist.
    debug (bool): The status of the webhook.
    webhook_branches (List[str]): List of branch names to configure webhook(s) for (defaults to self.branches).
    jenkins_base_url (str): The base URL of the Jenkins server.
    webhook_url (str): The URL of the webhook.
    group (str): The group of the project.
    project_name (str): The name of the project.

Methods:
    __init__(self): Initializes the GitLab API Python Client.
    _get_project_id(self,return_id: bool = False) -> Optional[int]: Gets the project ID from the project name.
    _get_project_name(self): Gets the project name from the project ID.
    _get_protected_branches(self): Gets the protected branches from the project ID.
    _perform_request(self, method, url, data=None): Performs a request.       
    _get_project_info(self): Gets the project information.
    _get_project_id(self): Gets the project ID from the project name.
    _get_protected_branches(self): Gets the protected branches from the project ID.
    _get_branches(self, return_name=False) -> Union[List[str], Dict[str, Any]]: Gets the branches from the project ID.
    _create_branch(self, branch_name, from_branch="master") -> None: Creates a branch.
    protect_branches(self): Protects the branch, with specified permissions.
    create_branches(self): Creates the branches if they do not exist.
    _get_hooks(self) -> List[Dict[str, Any]]: Gets the hooks from the project ID. 
    configure_webhooks(self): Configures the webhooks.
"""


class PyGit:
    def __init__(self):
        """Initializes PyGit. No arguments required as they are passed in via CLI flags"""

        self.parser = ArgumentParser()
        self.parser.add_argument(
            "-p", "--project", help="Project to search for", required=False
        )
        self.parser.add_argument(
            "-pid",
            "--project-id",
            type=int,
            help="The Git project ID(s)",
            required=False,
        )
        self.parser.add_argument(
            "-t", "--token", help="The Git API token", type=str, required=False
        )
        self.parser.add_argument("--debug", type=bool, default=False, help="Debug mode")
        self.parser.add_argument(
            "-b",
            "--branches",
            nargs="+",
            help="Branch names to configure webhook(s)",
            required=False,
            default=[],
        )
        self.parser.add_argument(
            "-c",
            "--create-branches",
            type=bool,
            default=False,
            help="Create branches for each branch name",
        )
        self.parser.add_argument(
            "-X",
            "--debug-out",
            type=bool,
            default=False,
            help="Print various stage of execution",
        )
        self.args = self.parser.parse_args()
        if not any((self.args.project, self.args.project_id)):
            exit("You must specify the project or project ID")

        self.project_name = self.args.project
        self.project_id = self.args.project_id
        self.token = self.args.token
        self.debug = self.args.debug_out
        self.webhook_branches = self.args.branches
        self.should_create_branches = self.args.create_branches

        if not self.token:
            if not os.getenv("GIT_TOKEN"):
                exit(
                    "You must specify a token or set the GIT_TOKEN environment variable"
                )
            self.token = os.getenv("GIT_TOKEN")

        self.project_info = {}
        if self.project_name:
            self._get_project_info(by_name=True)
            self._get_project_id()
        elif self.project_id:
            # self.project_ids = {self.project_id}
            self._get_project_info(by_id=True)

        self.pp = pprint.PrettyPrinter(indent=4)

    @property
    def base_url(self) -> str:
        return "https://gitlab.agilesof.com"

    @property
    def jenkins_base_url(self) -> str:
        return "https://jenkins-agiledagger-jenkins.apps.dev.agiledagger.io"

    @property
    def protected_branches(self) -> set:
        """
        Get the protected branches that were agreed on (GitFlow)
        """
        return {"master", "release", "qa", "development"}

    @property
    def group(self) -> str:
        """
        Get the group ID
        """
        if not self.project_info:
            raise Exception("No project info")
        return self.project_info.get("namespace", {}).get("path")

    @property
    def name(self) -> str:
        """
        Get the repo name
        """
        if not self.project_info:
            raise Exception("No project info 3")
        return self.project_info.get("name", "").lower()

    @property
    def webhook_url(self) -> str:
        return f"{self.jenkins_base_url}/project/{self.group}-cicd/{self.group}-cicd-{self.name}-pipeline"

    def _perform_request(
        self, url, method="GET", data=None, return_json=True
    ) -> Optional[Dict[str, Any]]:
        """
        Perform the request
        """
        headers = {"PRIVATE-TOKEN": self.token}
        if self.debug:
            print("Request URL: %s" % url)
            print("Request Data: %s" % data)
        r = requests.request(method, url, headers=headers, data=data)
        # if self.debug:
        #     print("Response: %s" % r.text)
        if 200 <= r.status_code <= 299:
            return r.json() if return_json else None
        else:
            # sometime GitLab returns a non 200 but the request actually succeeded
            print(f"Error performing request\n{url}: {r.status_code}")
            return None

    def _get_project_info(self, by_id=False, by_name=False) -> Optional[Dict[str, Any]]:
        """
        Get the project info from the project ID
        """

        if self.debug:
            print("Getting project info")

        if by_name:
            url = "{}/api/v4/projects?search={}".format(
                self.base_url, self.project_name
            )
        elif by_id:
            url = "{}/api/v4/projects/{}".format(self.base_url, self.project_id)
        else:
            exit("You must specify a project by ID or name")

        r = self._perform_request(url=url, method="GET")

        if type(r) == dict:
            self.project_info = r
        elif type(r) == list:
            # Make sure we only have one project (no forks)
            for data in r:
                # print(data)
                if "forked_from_project" in data:
                    continue
                self.project_info = data
        else:
            print("No project info")
            return None

    def _get_project_id(self, return_id: bool = False) -> Optional[int]:
        """
        Get the project ID from the project_info
        """

        for k, v in self.project_info.items():
            if k == "id":
                self.project_id = v
        if return_id:
            return self.project_id

    def _get_protected_branches(self) -> List[str]:
        """
        Get the protected branches
        """
        if not self.project_id:
            exit("No project id")
        url = "{}/api/v4/projects/{}/protected_branches".format(
            self.base_url, self.project_id
        )
        branches = self._perform_request(url=url, method="GET")
        if not branches:
            return []
        if self.debug:
            [self.pp.pprint(b) for b in branches]
        return [b.get("name") for b in branches]

    def _get_branches(self, return_name=False) -> Union[List[str], Dict[str, Any]]:
        """
        Get the branches from the project ID
        """
        if not self.project_id:
            exit("No project IDs")

        url = "{}/api/v4/projects/{}/repository/branches".format(
            self.base_url, self.project_id
        )
        branches = self._perform_request(url=url, method="GET")
        if not branches:
            return []

        if return_name:
            branche_names = set()
            [branche_names.add(b.get("name")) for b in branches]
            if self.debug:
                msg = "Branches: %s" % list(branche_names)
                print(f"\n{msg}")
                print("-" * len(msg) + "\n")
            return branche_names

        if self.debug:
            print("Get branches for ID: %s" % self.project_id)
            [self.pp.pprint(b) for b in branches]

        return branches

    def _create_branch(self, branch_name, from_branch="master") -> None:
        """
        Create a branch
        """
        if not self.project_id:
            exit("No project ID 5")

        url = "{}/api/v4/projects/{}/repository/branches".format(
            self.base_url, self.project_id
        )
        data = {"branch": branch_name, "ref": from_branch}
        r = self._perform_request(url=url, method="POST", data=data)
        if not r:
            print("No response")
            return
        if self.debug:
            print("Create branch: %s" % r)

    def create_branches(self) -> None:
        """
        Create the branches
        """
        if not self.project_id:
            exit("No project ID 6")

        branches = self._get_branches(return_name=True)
        if self.debug:
            print("Create branches: %s" % branches)

        branches_to_create = self.protected_branches - branches
        if self.debug:
            print("Branches to create: %s" % branches_to_create)

        for branch in branches_to_create:
            self._create_branch(branch)

        if branches_to_create:
            print("Branch structure does not adhere to AgileDagger")
            if not self.should_create_branches:
                return

        for branch in branches_to_create:
            if self.debug:
                print("Create branch: %s" % branch)
            self._create_branch(branch)

    def _get_hooks(self) -> List[Dict[str, Any]]:
        """
        Get the hooks
        """
        if not self.project_info:
            exit("No project info 4")
        url = "{}/api/v4/projects/{}/hooks".format(self.base_url, self.project_id)
        if self.debug:
            print("Get WebHook(s) for %s\nGitLab URL: %s" % (self.project_id, url))

        r = self._perform_request(url=url, method="GET")
        if not r:
            print("No response")
            return []
        return r

    def configure_webhooks(self) -> List[Dict[str, Any]]:
        """
        Configure webhooks for the project
        """
        if self.debug:
            print("Configure webhooks for %s" % self.webhook_url)

        hooks = self._get_hooks()
        if hooks:
            for hook in hooks:
                if hook.get("url") == self.webhook_url:
                    print("Webhook already configured")
                    # This logic will surely fail once we have multiple webhooks
                    # return

        # should I create a webhook for every branch?
        # The only branch that can be pushed to is ad/AD branches (if configured properly)
        if not self.webhook_branches:
            self.webhook_branches = self.protected_branches

        responses = []
        _branches = ["|".join(self.webhook_branches), "ad/*", "AD/*"]
        # GitLab 11.9.2 does not appear to support the use of OR and WILDCARD in the same filter
        # If protected branches are configured properly, then we do not need to use the OR filter on protected branches
        for branch in _branches:
            data = {
                "url": self.webhook_url,
                "push_events": True,
                "merge_requests_events": False
                if any(_x in branch for _x in ["ad", "AD"])
                else True,
                "enable_ssl_verification": True,
                "project_id": self.project_id,
                "push_events_branch_filter": branch,
            }
            if self.debug:
                print("Configure Webhooks")
                self.pp.pprint(data)
            url = "{}/api/v4/projects/{}/hooks".format(self.base_url, self.project_id)
            if self.debug:
                print(
                    "Configure WebHook(s) for %s\nGitLab URL: %s\nJenkins URL: %s"
                    % (self.project_id, url, self.webhook_url)
                )

            r = self._perform_request(url=url, method="POST", data=data)
            if not r:
                print("No response")
            else:
                responses.append(r)
        return responses

    def protect_branch(
        self,
        branch: str,
        push_access_level: int,
        merge_access_level: int,
        method="POST",
    ) -> Optional[Dict[str, Any]]:
        """Ensure that a protected branch is configured properly"""
        # descriptions = {0: "No one", 30: "Developers + Maintainers", 40: "Maintainers"}
        url = "{}/api/v4/projects/{}/protected_branches".format(
            self.base_url, self.project_id
        )
        data = {
            "name": branch,
            "push_access_level": f"{push_access_level}",
            "allowed_to_merge": f"{merge_access_level}",
        }
        if self.debug:
            self.pp.pprint(data)
        try:
            r = self._perform_request(url=url, method=method, data=data)
        except Exception as e:
            print(e)
            return False
        if not r:
            print("No response")
            return False
        return r

    def _unprotect_branch(self, name) -> Optional[Dict[str, Any]]:
        """Unprotect a branch"""
        url = "{}/api/v4/projects/{}/protected_branches/{}".format(
            self.base_url, self.project_id, name
        )
        if self.debug:
            print(f"Unprotect Branch: {url}")
        r = self._perform_request(url=url, method="DELETE", return_json=False)
        if not r:
            print("No response")
            return None
        return r

    def unprotect_branches(self) -> None:
        branches_to_unprotect = self._get_protected_branches()
        for branch in branches_to_unprotect:
            print(f"Unprotectiing branch: {branch}")
            if branch not in self.protected_branches:
                continue
            try:
                self._unprotect_branch(branch)
            except Exception as e:
                print(e)
