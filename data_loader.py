import os
import sys
import json

from setting import *


def load_project(language):
    # Generate the file path based on the language parameter
    file_path = os.path.join(DATA_FOLDER, f'verified_cve_with_versions_{language}.json')

    # Open and load the corresponding JSON file
    with open(file_path) as fin:
        cve_c_data = json.load(fin)

    projects = set()

    for entry in cve_c_data:
        project_name = entry.get("project")
        if project_name:
            projects.add(project_name)

    unique_projects = sorted(list(projects))
    return unique_projects

def load_annotated_commits(target_projects=None):
    # Get all files in DATA_FOLDER that start with 'verified_cve_with_versions_'
    all_files = [f for f in os.listdir(DATA_FOLDER) if f.startswith('verified_cve_with_versions_')]

    merged_data = []

    # Load each file and append its data to merged_data
    for file_name in all_files:
        file_path = os.path.join(DATA_FOLDER, file_name)

        # Check if the file is empty
        if os.path.getsize(file_path) == 0:
            print(f"Warning: The file {file_name} is empty, skipping.")
            continue

        try:
            with open(file_path) as fin:
                cve_data = json.load(fin)
                merged_data.extend(cve_data)
        except json.JSONDecodeError as e:
            print(f"Error loading JSON from file {file_name}: {e}")
            continue

    project_commits = {}

    # Process the merged data
    for item in merged_data:
        project_name = item['project']
        fixing_commits = [fixing['fixing_commit'] for fixing in item['fixing_details']]

        if project_name in project_commits:
            project_commits[project_name].extend(fixing_commits)
        else:
            project_commits[project_name] = fixing_commits

    return project_commits

def read_cve_commits(project, cve_fix_commits):
    cve_commits = cve_fix_commits[project]['cves']
    
    all_valid_commits = []
    for cve_id in cve_commits:
        if 'fix_details' not in cve_commits[cve_id]:
            print(project, ' invalid')
            break

        fixes = cve_commits[cve_id]['fixes']
        fixes_detail = cve_commits[cve_id]['fix_details']

        valid_fixes = [fix['commit_id'] for fix in fixes_detail]

        all_valid_commits.extend(valid_fixes)
    
    return list(set(all_valid_commits))

def fixing_commit_to_cve(target_projects=None):
    # Get all files in DATA_FOLDER that start with 'verified_cve_with_versions_'
    all_files = [f for f in os.listdir(DATA_FOLDER) if f.startswith('verified_cve_with_versions_')]

    merged_data = []

    # Load each file and append its data to merged_data
    for file_name in all_files:
        file_path = os.path.join(DATA_FOLDER, file_name)
        # Check if the file is empty
        if os.path.getsize(file_path) == 0:
            print(f"Warning: The file {file_name} is empty, skipping.")
            continue

        try:
            with open(file_path) as fin:
                cve_data = json.load(fin)
                merged_data.extend(cve_data)
        except json.JSONDecodeError as e:
            print(f"Error loading JSON from file {file_name}: {e}")
            continue

    fixing_commit_to_cve = {}
    # Process the merged data
    for item in merged_data:
        # Map fixing commits to CVE IDs
        for fixing in item['fixing_details']:
            fixing_commit_to_cve[fixing['fixing_commit']] = item["cve_id"]

    return fixing_commit_to_cve

fixing_commit_to_CVE = fixing_commit_to_cve()


ANNOTATED_COMMITS = load_annotated_commits()