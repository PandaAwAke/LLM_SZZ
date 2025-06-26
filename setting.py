import sys
import os

# config your working folder and the correponding folder
WORK_DIR = 'LLM_SZZ/'

REPOS_DIR = 'LLM_SZZ/repos'  

DATA_FOLDER = os.path.join(WORK_DIR, 'data/') 

SZZ_FOLDER = os.path.join(WORK_DIR, 'SZZ') 

DEFAULT_MAX_CHANGE_SIZE = sys.maxsize

AST_MAP_PATH = os.path.join(WORK_DIR, 'ASTMapEval_jar')

LOG_DIR = os.path.join(WORK_DIR, 'GitLogs')


FLUCTUATION = 0

