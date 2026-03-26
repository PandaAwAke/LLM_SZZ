import logging
import os
import sys  
import json  
import statistics  
import sys
from time import perf_counter

from setting import *
from data_loader import REPOS_DIR 
from log_generation import GitLog  
import argparse

def convert_project_name(project):
    if "/" in project:
        return project.replace("/", "_")
    else:
        return project

class DualOutput:
    def __init__(self, filename, terminal=sys.stdout):
        self.file = open(filename, "a")
        self.terminal = terminal

    def write(self, message):
        self.terminal.write(message)
        self.file.write(message)

    def flush(self): 
        self.terminal.flush()
        self.file.flush()


logger = logging.getLogger('llm-szz')
logger.setLevel(logging.INFO)  # 设置日志级别
logger.propagate = False  # 关键：阻止日志向上传播到全局logger
file_handler = logging.FileHandler('llm-szz.log', encoding='utf-8')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


def eval_vulnerable_version(lang=None, szz_method=None, model = None,time = None):
    with open(os.path.join(DATA_FOLDER, f'verified_cve_with_versions_{lang}.json')) as fin:
        labeled_items = json.load(fin)
    
    print(szz_method) 

    correct_c = set() 
    correct_all = []  
    
    identified_c = set() 
    identified_all = [] 


    n_correct_commit = 0 
    n_szz_fail = 0


    def get_real_project(project: str) -> str:
        with open('repo_mapping.json', 'r', encoding='utf-8') as f:
            repo_mapping = json.load(f)
        if project in repo_mapping:
            repo_url = repo_mapping[project]
            real_project = repo_url.rstrip('/').split('/')[-1]
            return real_project
        return project
    
    

    for item in labeled_items:
        stat_time_start = perf_counter()


        print("*******************")
        project = item['project'] 
        print("project:",project)



        # pro_name = convert_project_name(project)
        pro_name = get_real_project(project)

        try:
            
            if szz_method =="llm":
                file_path = os.path.join(WORK_DIR, f"results/{szz_method}-szz/{lang}/{model}/{time}/{szz_method}-{pro_name}.json")
                with open(file_path) as fin:
                 
                    szz_results = json.load(fin) 
            else:
                with open(os.path.join(WORK_DIR, f"results/{szz_method}-szz/{lang}/{time}/{szz_method}-{pro_name}.json")) as fin:
                    szz_results = json.load(fin) 
                    

        except:
            continue

        SZZ_fail = False 
        
        inducing_commits = set() 

        szz_commits = set()

        
       
        for fd in item['fixing_details']: 
            fixing_commit = fd['fixing_commit'] 
            print("fixing_commit:",fixing_commit)
            if fixing_commit not in szz_results:

                SZZ_fail = True 
                continue
            

            szz_vic = szz_results[fixing_commit]  
            if szz_method == 'llm': 
                szz_vic = []
                szz_vic_info = []
                for record in szz_results[fixing_commit]:
                    szz_vic.append(record["previous_commits"][-1]["commit"])

                print(szz_vic)
                
            if szz_method == 'v' : 
                szz_vic = []
                szz_vic_info = []
                for record in szz_results[fixing_commit]:
                    szz_vic.append(record["previous_commits"][-1]["commit"]) 
                print(szz_vic)
                    
                     
            szz_commits |= set(szz_vic) 
            
            

            for ic in fd['inducing_commits']:
                if ic['is_true_inducing'] == 'True': 
                    inducing_commits.add(ic['commit_id'])

        stat_time_end = perf_counter()
        logger.info(f"[Time] CVE {item["cve_id"]} time: {stat_time_end - stat_time_start}")

         

        

        sorted_szz_vic = sorted(list(szz_commits), key=lambda k: GitLog().get_commit_time(os.path.join(REPOS_DIR, project), k)) 
        print("sorted_szz_vic",sorted_szz_vic)
        print("len(sorted_szz_vic)",len(sorted_szz_vic))
       


        if SZZ_fail:
            n_szz_fail += 1 
            continue
        

        sorted_inducing_commits = sorted(list(inducing_commits), key=lambda k: GitLog().get_commit_time(os.path.join(REPOS_DIR, project), k))  
        print("sorted_inducing_commits",sorted_inducing_commits)
        print("len(sorted_inducing_commits)",len(sorted_inducing_commits))
        if len(sorted_inducing_commits) <= 0:
            continue

        true_vic = sorted_inducing_commits[0] 
        correct_c.add(true_vic) 
        correct_all.extend(sorted_inducing_commits)
        identified_c = identified_c | set(sorted_szz_vic) 
        identified_all.extend(sorted_szz_vic)

        intersection = set([true_vic]).intersection(sorted_szz_vic) 
        if len(intersection) > 0:
            n_correct_commit += 1 


    intersection = correct_c.intersection(identified_c) 
    recall_c = len(intersection) * 1.0 / len(correct_c) 
    precision_c = len(intersection) * 1.0 / len(identified_c) 
    recall2 = n_correct_commit *1.0 / len(correct_all)
    precision2 = n_correct_commit *1.0 / len(identified_all)
    

    print("len(intersection)",len(intersection))
    print("len(correct_c)---total true_inducing_commit-paper algorithm",len(correct_c))
    print("len(correct_all)---total true_inducing_commit-non-deduplicated algorithm",len(correct_all))
    print("len(identified_c)-total szz identification-paper algorithm",len(identified_c))
    print("len(identified_all)-total szz identification-non-deduplicated algorithm",len(identified_all))
    
    


    c=[n for n in correct_all if correct_all.count(n) > 1]
    list2=list(set(c))
    F1_score1 =  2 * (precision_c * recall_c) / (precision_c + recall_c)
    F1_score2 =  2 * (precision2 * recall2) / (precision2 + recall2)
    print("Cases of duplicate bug inducing commits:",list2)
    print("\n")
    print("szz_method:"+ szz_method +"szz "+ "in "+lang + '\n') 

    print('correct_commit:{0}, total inducing_commit:{1}, szz_fail:{2}\n'.format(n_correct_commit,len(correct_all), n_szz_fail)) 
    print('Incorrect algorithm (deduplicated): recall_c:{0}, precision_c:{1},F1-score:{2}\n'.format(recall_c, precision_c,F1_score1)) 
    
 
    print('Correct algorithm (non-deduplicated): recall_c:{0}, precision_c:{1},F1-score:{2}\n'.format(recall2, precision2,F1_score2)) 


    return n_correct_commit, n_szz_fail, recall_c, precision_c, recall2, precision2  

import argparse

def print_parser(method, model, language, time, levenshtein_num):
    print(f"Method: {method}")
    print(f"Model: {model}")
    print(f"Language: {language}")
    print(f"Time: {time}")
    print(f"Levenshtein_num: {levenshtein_num}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process some parameters.')
    

    parser.add_argument('--method', type=str, default='llm', help='Method to use (default: llm)')
    parser.add_argument('--model', type=str, default='deepseek-chat', help='Model to use (default: deepseek-chat)')
    parser.add_argument('--language', type=str, default='Java', choices=['C', 'Java','py','php','js'], help='Programming language (default: Java)')
    parser.add_argument('--time', type=str, default='x1', help='Time setting (default: x1)')
    parser.add_argument('--levenshtein_num', type=float, default=0.5, help='Levenshtein number (default: 0.5)')
     

    args = parser.parse_args()


    print_parser(args.method, args.model, args.language, args.time, args.levenshtein_num)

    METHOD = args.method
    MODEL = args.model
    LANGUAGE = args.language  
    TIME = args.time 
    Levenshtein_num = args.levenshtein_num
    
    if METHOD == "llm":
        sys.stdout = DualOutput('results/evaluate_results/{METHOD}-szz__{language}__{MODEL}__eval__log__{time}.txt'.format(METHOD=METHOD,language=LANGUAGE,MODEL=MODEL,time=TIME))
    else:
        sys.stdout = DualOutput('results/evaluate_results/{METHOD}-szz__{language}__eval__log__{time}.txt'.format(METHOD=METHOD,language=LANGUAGE,time=TIME))
  

    results = eval_vulnerable_version(lang = LANGUAGE, szz_method=METHOD,model = MODEL,time = TIME) 





