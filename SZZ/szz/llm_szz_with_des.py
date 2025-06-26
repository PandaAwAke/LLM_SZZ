import os
import re
import sys
import logging as log
import traceback
from typing import List, Set
import subprocess
import json
import subprocess

from git import Commit

from szz.core.abstract_szz import AbstractSZZ, ImpactedFile
from szz.core.llm import LLM
from data_loader import fixing_commit_to_CVE

from pydriller import ModificationType, GitRepository as PyDrillerGitRepo

import Levenshtein
from collections import Counter



def remove_whitespace(line_str):
    return ''.join(line_str.strip().split())

def compute_line_ratio(line_str1, line_str2):
    l1 = remove_whitespace(line_str1)
    l2 = remove_whitespace(line_str2)
    return Levenshtein.ratio(l1, l2)

def add_line_numbers_to_hunk(hunk):

    lines = hunk.split("\n")

    header = lines[0]
    _, ranges, _ = header.split("@@", 2)
    old_range, new_range = ranges.split(" ")[1:3] 
    old_start, old_count = (int(n) for n in old_range[1:].split(","))
    new_start, new_count = (int(n) for n in new_range[1:].split(","))


    old_line = old_start
    new_line = new_start
    annotated_lines = []


    for line in lines[1:]:
        if line.startswith("-"):
            annotated_lines.append(f"{old_line: <8} ")
            old_line += 1
        elif line.startswith("+"):
            annotated_lines.append(f"{' ': <6}{new_line}")
            new_line += 1
        else:
            annotated_lines.append(f"{old_line: <6}{new_line}")
            old_line += 1
            new_line += 1


        annotated_lines[-1] += f" {line}"

    return "\n".join(annotated_lines)


def extract_last_number(s):
    numbers = re.findall(r'-?\d+', s)
    if numbers:
        return int(numbers[-1])
    else:
        return -1
    
prompt1 = """
# Identification of the Root Cause Deleted Line         
 
## Inputs Provided
CVE Descriptions
   {cve_detail}

## Output Format
The output should be in JSON format, and the template is provided below:
{{
    "understand_of_CVE":"", 
    "analysis": [
        {{
            "id": "1",
            "assessment": "[Impossible/Possible/Highly Probable]",
            "explanation": ""
        }},
        {{
            "id": "2",
            "assessment": "[Impossible/Possible/Highly Probable]",
            "explanation": ""
        }}
    ],
    "likely_root_cause": {{
        "id": "2",
        "explanation": "",
        "result": "2"
    }}
}}

## Your Task
You are required to generate an output in JSON format following these instructions:
1. Analyze the provided CVE descriptions to understand the nature of Bug A. Assign the result to the key "understanding_of_CVE".
2. I will provide [a list of potential deleted lines] that may contain the root cause of the bug, with each line containing both an id and a line string. Please evaluate the likelihood of each line being the root cause of Bug A:
   Note that if the candidate line is a comment line in the code, then its assessment must be impossible.
   - For each line, you should give the following information:
        {{
            "id": "",
            "assessment": "[Impossible/Possible/Highly Probable]",
            "explanation": ""
        }},
        
[a list of potential deleted lines]:

```
   {possible_line_str}
```
        
3. Identify the line that is most likely to be the root cause of the bug and return its id.
    - provide:
        "likely_root_cause": {{
            "id": "",
            "explanation": "",
            "result": ""
            }}



"""
prompt3 = """
# Optimal Candidate Selection 

## Inputs Provided

[CVE descriptions]
        {cve_detail}



## Output Format
The output should be in JSON format, and the template is provided below:
{{
    "understand_of_CVE":"",

    "analysis": [        
        {{
            "line_num": "/* expected to be an integer */",
            "assessment": "[Impossible/Possible/Highly Probable]",
            "explanation": ""
        }},
        {{
            "line_num": "/* expected to be an integer */",
            "assessment": "[Impossible/Possible/Highly Probable]",
            "explanation": ""
        }}
    ],
    "likely_root_cause": {{
        "explanation": "",
        "line_num": "/* expected to be an integer */",  
    }}
}}

## Your Task
You are required to generate an output in JSON format following these instructions:

**Step 1**: You will receive the CVE descriptions. Your task is to analyze these details to understand the nature of the bug, which we'll refer to as Bug A. Assign the result to the key "understanding_of_CVE".


**Step 2**: Next, I will provide you with several [lines from descendant commit] in different files, which may contain and potentially evolve into Bug A.  Your task is to examine each deleted line alongside its context, evaluating the likelihood of containing Bug A and providing a rationale. Evaluate each potential line from list{possible_line}. 
  Note that if the candidate line is a comment line in the code, then its assessment must be impossible.
  - For each line, provide the following information:
        {{
            "line_num": "/* expected to be an integer */",
            "assessment": "[Impossible/Possible/Highly Probable]",
            "explanation": ""
        }},
        
[lines from descendant commit]:       
```
{candidates} 
```


**Step 3**: Summarize the findings. Identify the line number from list{possible_line} that is most likely to contain Bug A. 
    - provide:
        "likely_root_cause": {{
            "explanation": "",
            "line_num": "/* expected to be an integer */",
            }}


    
"""

prompt2 = """
# Vulnerability Backtrace Decision

## Input Provided
**Step 1**: 
[CVE descriptions]
        {cve_detail}

## Output Format
The output should be in JSON format, and the template is provided below:
{{
    "understand_of_CVE":"",
    "analysis": [
        {{
            "line_num": "/* expected to be an integer */",
            "assessment": "[Impossible/Possible/Highly Probable]",
            "explanation": ""
        }},
        {{
            "line_num": "/* expected to be an integer */",
            "assessment": "[Impossible/Possible/Highly Probable]",
            "explanation": ""
        }}
    ],
    "likely_root_cause": {{
        "explanation": "",
        "line_num": "-1", --> choose a line_num from {possible_line}
    }}
}}


## Your Task
You are required to generate an output in JSON format following these instructions:

**Step 1: Bug Analysis**
    Analyze the provided CVE descriptions to understand and describe the nature of Bug A. Assign the result to the key "understanding_of_CVE".


**Step 2: Line Evaluation**
    I will provide you [diff of candidate deleted lines], potentially related to Bug A. 
    1. You need to examine the context of each deleted line numbered {possible_matched_line}.
    2. Determine whether each line could contain Bug A, categorizing the likelihood as [Impossible/Possible/Highly Probable]. It's important to note that none of these lines may contain the bug.
    3. Provide reasoning for each categorization, supporting your decision.
    Note that if the candidate line is a comment line in the code, then its assessment must be impossible.
    - For deleted line numbered {possible_matched_line}, provide the following information:
    {{
        "line_num": "/* expected to be an integer */",
        "assessment": "[Impossible/Possible/Highly Probable]",
        "explanation": ""
    }},
    [diff of candidate deleted lines]:
    ```
    {candidate_diff} 
    ```
   
**Step 3: Findings Summary**
    - Return `-1` if none of the lines contains Bug A, specifically if none are classified as Highly Probable.
    - Return the line number most likely to contain Bug A, if such a line exists.
    - provide:
    "likely_root_cause": {{
        "explanation": "",
        "line_num": "/* expected to be an integer */",
        }}
 
"""



def vote(times, model, text):
    times = 5
    result = []
    print(text)


    for i in range(3):
        output = model.run_model(text)
        print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% MODEL OUTPUT {} %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%".format(i+1))
        print(output)
        output_num = extract_last_number(output)  
        result.append(output_num)


    count = Counter(result)
    if count.most_common(1)[0][1] >= 3:
        final_result = count.most_common(1)[0][0]
        print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% VOTE RESULT %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
        print("result list:", result)
        print("Final answer after 3 runs:", final_result)
        return final_result
    

    output = model.run_model(text)
    print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% MODEL OUTPUT 4 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
    print(output)
    output_num = extract_last_number(output)
    result.append(output_num)

    count = Counter(result)
    if count.most_common(1)[0][1] >= 3:
        final_result = count.most_common(1)[0][0]
        print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% VOTE RESULT %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
        print("result list:", result)
        print("Final answer after 4 run:", final_result)
        return final_result


    output = model.run_model(text)
    print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% MODEL OUTPUT 5 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
    print(output)
    output_num = extract_last_number(output)
    result.append(output_num)


    count = Counter(result)
    final_result = count.most_common(1)[0][0]
    
    print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% VOTE RESULT %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
    print("result list:", result)
    print("Final answer after 5 run:", final_result)

    return final_result





MAXSIZE = sys.maxsize

class LLMSZZ(AbstractSZZ):
    """
    My SZZ implementation.

    Supported **kwargs:

    * ignore_revs_file_path

    """

    def __init__(self, repo_full_name: str, repo_url: str, repos_dir: str = None, use_temp_dir: bool = True, ast_map_path = None , model = None , Levenshtein_num = None ):
        super().__init__(repo_full_name, repo_url, repos_dir, use_temp_dir)
        self.ast_map_path = ast_map_path
        self.model = model
        self.Levenshtein_num = Levenshtein_num
        
    def find_diff_message(self,fix_commit_hash: str):
        fixing_commit_diff = ""
        commit = PyDrillerGitRepo(self.repository_path).get_commit(fix_commit_hash)
        for mod in commit.modifications:
            fixing_commit_diff = fixing_commit_diff + mod.diff
        return fixing_commit_diff

    def get_cve_detail(self, cve):
        file_path = '/data1/cvelistV5-main/' + cve + '.json'
        with open(file_path, 'r') as file:
            data = json.load(file)
        descriptions = data['containers']['cna']['descriptions'][0]['value']
        detail = "{}'s descriptions: {}\n".format(cve,descriptions)
        print("type = " + data['containers']['cna']['problemTypes'][0]['descriptions'][0]['type'])
        if data['containers']['cna']['problemTypes'][0]['descriptions'][0]['type'] == 'CWE':
            print(cve)
            cwe = data['containers']['cna']['problemTypes'][0]['descriptions'][0]['description']
            detail += "CWE Type: " + cwe + '\n'
        return detail

    def find_bic(self, fix_commit_hash: str, impacted_files: List['ImpactedFile'], **kwargs) -> Set[Commit]:
        """
        Find bug introducing commits candidates.

        :param str fix_commit_hash: hash of fix commit to scan for buggy commits
        :param List[ImpactedFile] impacted_files: list of impacted files in fix commit
        :key ignore_revs_file_path (str): specify ignore revs file for git blame to ignore specific commits.
        :returns Set[Commit] a set of bug introducing commits candidates, represented by Commit object
        """

        log.info(f"find_bic() kwargs: {kwargs}")

        ignore_revs_file_path = kwargs.get('ignore_revs_file_path', None)
     


        fixing_commit_diff = ""
        commit = PyDrillerGitRepo(self.repository_path).get_commit(fix_commit_hash)
        for mod in commit.modifications:
            fixing_commit_diff = fixing_commit_diff + mod.diff
        commit_message = commit.msg

        cve = fixing_commit_to_CVE[fix_commit_hash]


        self.cve_detail = self.get_cve_detail(cve)

        bug_inducing_commits = []
        for imp_file in impacted_files:

            try:
                blame_data = self._blame(

                    rev='{commit_id}^'.format(commit_id=fix_commit_hash),
                    file_path=imp_file.file_path,
                    modified_lines=imp_file.modified_lines,
                    ignore_revs_file_path=ignore_revs_file_path,
                    ignore_whitespaces=True,
                    skip_comments=True
                ) 
            except:
                print(traceback.format_exc())
                
            if len(blame_data)>1: 
                possible_line = []  
                num = 0
                for entry in blame_data:
                    if entry.line_str == '':
                        continue
                    num += 1
                    possible_line.append({"id": str(num), "line_str": entry.line_str,"entry":entry})
                
                possible_line_str = ""
                for p in possible_line:
                    possible_line_str+="id= {id} , line_str='{line_str}' \n".format(id = str(p["id"]),line_str = p["line_str"])
                    
                text = prompt1.format(possible_line_str = possible_line_str,fixing_commit_diff = fixing_commit_diff,cve_detail=self.cve_detail)
    
           
                print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% Identification of the Root Cause Deleted Line %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
                print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% MODEL INPUT (prompt1) %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")

               
                model = LLM(model=self.model)

                output_num = vote(5, model, text)
                
                target_entry = None

                for item in possible_line:
                    if item['id'] == str(output_num):
                        target_entry = item['entry']
                        break 
                

                if target_entry :
                    blame_data = []
                    blame_data.append(target_entry)
                    print("成功发现一个根本原因删除行")
                else:
                    print("未成功提取根本原因删除行")
                    
    
               

            for entry in blame_data: 

                if entry.line_str == '':
                        continue
                previous_commits = []
                
                blame_result = entry
                while True:

                    mapped_line_num = self.map_modified_line(blame_result, imp_file.file_path,fixing_commit_diff,commit_message)
                    previous_commits.append({"commit":blame_result.commit.hexsha, "line number": blame_result.line_num,"line content":blame_result.line_str,"hunk(diff message)":blame_result.hunk,})
                
                    if mapped_line_num == -1:
                        break
                    
                    blame_data2 = None
                    try:
                        blame_data2 = self._blame(
                                        rev='{commit_id}^'.format(commit_id=blame_result.commit.hexsha),
                                        file_path=imp_file.file_path,
                                        modified_lines=[mapped_line_num],
                                        ignore_revs_file_path=ignore_revs_file_path,
                                        ignore_whitespaces=True,
                                        skip_comments=True
                                    )
                    except:
                        print(traceback.format_exc())
                        
                    blame_result = list(blame_data2)[0]
                    
                bug_inducing_commits.append({'line_num':entry.line_num, 'line_str': entry.line_str, 'file_path': entry.file_path,"content_around":entry.context_around_line, 'previous_commits': previous_commits})
            
            
        if len(bug_inducing_commits)>1:
            step_2 = """"""
            possible_line = []
            for entry in bug_inducing_commits:
                possible_line.append(entry['line_num'] )
                step_2+="-----------------------------------------\n"
                step_2 += "line num : " + str(entry['line_num'])  + "\n"
                step_2 += "content around: \n" + str(entry['content_around']) + "\n"
                
            if len(step_2)>3000:
                print("信息量太大，更换成不给上下文，只给行内容")
                step_2 = """"""
                for entry in bug_inducing_commits:
                    step_2+="-----------------------------------------\n"
                    step_2 += "line num : " + str(entry['line_num'])  + "\n"
                    step_2 += "line_str \n" + str(entry['line_str']) + "\n"
                
                
            text = prompt3.format(possible_line = possible_line ,fixing_commit_diff = fixing_commit_diff,candidates=step_2,cve_detail=self.cve_detail)
    

        
            print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% Optimal Candidate Selection %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
            print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% MODEL INPUT (prompt3) %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")

           
            model = LLM(model=self.model)
            output_num = vote(5, model, text)
            
            for entry in bug_inducing_commits:
                if entry['line_num']  == output_num:
                    c = []
                    c.append(entry)
                    bug_inducing_commits = c
                
        print("================================================== bug_inducing_commits ==================================================")
        print(bug_inducing_commits)
            
            
            
                    
        return bug_inducing_commits

  
    def map_modified_line(self, blame_entry, blame_file_path,fixing_commit_diff,commit_message):
        blame_commit = PyDrillerGitRepo(self.repository_path).get_commit(blame_entry.commit.hexsha)
        lines_deleted = list()
        best_matched_line = -1 
        for mod in blame_commit.modifications:
            if not mod.old_path:  
                continue
            file_path = mod.new_path 
            if mod.change_type == ModificationType.DELETE or mod.change_type == ModificationType.RENAME:
                file_path = mod.old_path

            if file_path != blame_file_path: 
                continue
            
            lines_added = [added for added in mod.diff_parsed['added']]
            delete = [deleted for deleted in mod.diff_parsed['deleted']]
            

            context = []
            for e in delete:

                blame_d = self._blame(
                    rev='{commit_id}^'.format(commit_id=blame_entry.commit.hexsha),
                    file_path=file_path,
                    modified_lines=[e[0]],
                    ignore_whitespaces=True,
                    skip_comments=True
                )
                for c in blame_d:
                    context = c.context_around_line
                    break


                hunk1 = ""
                hunks = mod.diff.split('\n@')

                hunks_adjusted = [hunks[0]] + ['@' + s for s in hunks[1:]]
             
                for hunk in hunks_adjusted:
                    line_number = e[0]
                    lines = hunk.split('\n')

                    start_line = int(lines[0].split(' ')[1].split(',')[0])*(-1)
                    hunk_lines = int(lines[0].split(' ')[1].split(',')[1])

                    if start_line <= line_number <= start_line + hunk_lines -1:
                        hunk1 = add_line_numbers_to_hunk(hunk)
                        break
                    
                de = e + (context,file_path,hunk1,)
                lines_deleted.append(de)
                               
             
            
        sorted_lines_deleted = ["the deleted line in this commit is blank or the descendant commit don't have deleted line"]
        
        possible_matched_line = []
        if blame_entry.line_str and len(lines_deleted): 
     
            sorted_lines_deleted = [(line[0], line[1], 
                                            compute_line_ratio(blame_entry.line_str, line[1]), 
                                            abs(blame_entry.line_num - line[0]))
                                        for line in lines_deleted]

            sorted_lines_deleted = sorted(sorted_lines_deleted, key=lambda x : (x[2], MAXSIZE-x[3]), reverse=True) 




            



            
            max_lines = min(5, len(sorted_lines_deleted))


            for lines in sorted_lines_deleted[:max_lines]:
                if lines[2] > self.Levenshtein_num:
                    possible_matched_line.append(lines[0])
                    
                    
                    
                            

        blame_method  =   "hunk"

        
        print("================================================== blame_entry ==================================================")

        print("blame_entry",blame_entry.commit.hexsha,"\nline num :",blame_entry.line_num,"\nline str:[",blame_entry.line_str,"]")
       
            
        if blame_method == "hunk":  

            possible_line = possible_matched_line + [-1]
            if len(possible_line)==1:
                best_matched_line = -1
                print("no possible line, return -1")
                return best_matched_line
            
            hunks = []
            candidate_diff = ""
            for line in lines_deleted:
                if line[4] not in hunks and line[0] in possible_matched_line:
                    candidate_diff += line[4]
                    candidate_diff += "\n"
                    hunks.append(line[4])
            

            if len(candidate_diff)>3000:
                
                
                best_matched_line = -1
                if sorted_lines_deleted[0][2] > 0.75:
                   best_matched_line = sorted_lines_deleted[0][0]
                   return best_matched_line
               

                

            
            text = prompt2.format(possible_matched_line=possible_matched_line,possible_line = str(possible_line),fixing_commit_diff = fixing_commit_diff,candidate_diff=candidate_diff,cve_detail=self.cve_detail)
                         
            print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% Vulnerability Backtrace Decision %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
            print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% MODEL INPUT (prompt2) %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
         
            model = LLM(model=self.model)

            output_num = vote(5, model, text)
            
            best_matched_line = output_num
                     

        
        return best_matched_line
        

        
            
  
                
                    