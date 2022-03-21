
# PyGit

```yaml
Author: Mitch Murphy
Date: 2021 Aug 25
```

## Summary
----

A lightweight Git client written in Python that can check branch structure on a repository, create branches if needed and setup and configure Webhooks.

### Flags

| Shorthand | Long                | Type     | Required | Default | Description                           |
|-----------|---------------------|----------|----------|---------|---------------------------------------|
| `-pid`    | `--project_id`      | Int      | False    |         | Project ID                            |
| `-p`      | `--project`         | String   | False    |         | Project Name                          |
| `-t`      | `--token`           | String   | True     |         | PAT with write permissions for repo   |
| `-D`      | `--debug`           | Boolean  | False    | False   | Print various stage of execution      |
| `-b`      | `--branches`        | List     | False    | `[]`    | Branch names to configure webhook(s)  |
| `-c`      | `--create-branches` | List     | False    | `[]`    | Create branches if not present        |

The `PyGit` class is really just a CLI tool, therefore, the initializer (`__init__` is not a constructor in Python, `__new__` is) sets up the argument parser, checks to make sure the necessary flags are set (`--token` and either `--project_id` or `--project`) and then queries the GitLab API in order to get the project info (needed only if the project name is passed instead of the Project ID). 

## User Guide

The user Guide covers all of `PyGit` by topic area. This tool is rather small, as is this guide. 

<br/>

### Attributes 

* `base_url` (str): The URL of the GitLab server.  
* `token` (str): The token used to authenticate with GitLab.  
* `project_id` (str): The ID of the project.  
* `project_name` (str): The name of the project.  
* `protected_branches` (List[str]): The list of protected branches (for AgileDagger).  
* `branches` (List[str]): List of branch names to configure webhook(s) for.  
* `create_branches` (bool): Whether or not to create branches if they do not exist.  
* `debug` (bool): The status of the webhook.  
* `webhook_branches` (List[str]): List of branch names to configure webhook(s) for (defaults to self.branches).  
* `jenkins_base_url` (str): The base URL of the Jenkins server.  
* `webhook_url` (str): The URL of the webhook.  
* `group` (str): The group of the project.  
* `project_name` (str): The name of the project.  

<br/>  

### Methods

* [__init__](#init) 
* [_get_project_id](#_get_project_id)(self,return_id: bool = False) -* Optional[int]: Gets the project ID from the project name.  
* [_get_project_name](#_get_project_name)(self): Gets the project name from the project ID.  
* [_get_protected_branches](#_get_protected_branches)(self): Gets the protected branches from the project ID.  
* [_perform_request](#_perform_request)(self, method, url, data=None): Performs a request.       
* [_get_project_info](#_get_project_info)(self): Gets the project information.  
* [_get_project_id](#_get_project_id)(self): Gets the project ID from the project name.  
* [_get_protected_branches](#_get_protected_branches)(self): Gets the protected branches from the project ID.  
* [_get_branches](#_get_branches)(self, return_name=False) -* Union[List[str], Dict[str, Any]]: Gets the branches from the project ID.  
* [_create_branch](#_create_branch)(self, branch_name, from_branch="master") -* None: Creates a branch.  
* [protect_branches](#protect_branches)(self): Protects the branch, with specified permissions.  
* [create_branches](#create_branches)(self): Creates the branches if they do not exist.  
* [_get_hooks](#_get_hooks)(self) -* List[Dict[str, Any]]: Gets the hooks from the project ID.   
* [configure_webhooks](#configure_webhooks)(self): Configures the webhooks.

----

## Usage
----

In order to use this client, you must either provide a token using the `--token` flag or create an environment variable `GIT_TOKEN`, and you need to either provide a `--project` (name) or `--project_id`. Below is an example of instantiating the class and calling various methods on it:

```python
pygit = PyGit()

# This method will only fully execute if the --create-branches flag is set to true
pygit.create_branches()

# In the event that there are already protected branches, we must first unprotect them and then re-protect them with 
# the proper permissions
pygit.unprotect_branches()

""" Protect Branches
    Make it so that every protected branch cannot be pushed to, only merged.
    40 equals maintainers only
    30 equals maintainers and developers
"""
for branch in (
    ("master", 0, 40),
    ("development", 0, 30),
    ("qa", 0, 40),
    ("release", 0, 40),
):
    pygit.protect_branch(branch[0], branch[1], branch[2])

""" Configure Webhooks

    Before you add a new one, first check if it already exists.
    If it does, delete/update it.
    If it doesn't, create it.
"""

pygit.configure_webhooks()
```

The above must be called with at least 2 flags (`--token` and either `--project_id` or `--project`), which has been encapsulated in a script which can be invoked using the above CLI flags as so: `./configure_project.py --token <TOKEN* --project brandi-flaskql --debug true --create-branches true --branches master release`
