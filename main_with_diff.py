import os
import sys
import json
import logging
import argparse
from typing import List, Dict, Optional, Any
from dataclasses import dataclass

from setting import *
sys.path.append(SZZ_FOLDER)

from szz.ag_szz import AGSZZ
from szz.b_szz import BaseSZZ
from szz.ma_szz import MASZZ, DetectLineMoved
from szz.v_szz import VSZZ
from szz.llm_szz_with_diff import LLMSZZ
from data_loader import load_annotated_commits, load_project


@dataclass
class SZZConfig:
    """Configuration class for SZZ parameters"""
    method: str
    model: str
    language: str
    time: str
    levenshtein_num: float
    max_change_size: int = DEFAULT_MAX_CHANGE_SIZE


class DualOutput:
    """Class to handle dual output to both terminal and file"""
    
    def __init__(self, filename: str, mode: str = 'w'):
        self.file = open(filename, mode)
        self.terminal_stdout = sys.stdout
        self.terminal_stderr = sys.stderr

    def write(self, message: str) -> None:
        """Write message to both terminal and file"""
        if hasattr(self.terminal_stdout, 'write'):
            self.terminal_stdout.write(message)
        if hasattr(self.terminal_stderr, 'write'):
            self.terminal_stderr.write(message)
        self.file.write(message)

    def flush(self) -> None:
        """Flush both terminal and file buffers"""
        if hasattr(self.terminal_stdout, 'flush'):
            self.terminal_stdout.flush()
        if hasattr(self.terminal_stderr, 'flush'):
            self.terminal_stderr.flush()
        self.file.flush()


class SZZRunner:
    """Main class to handle SZZ execution"""
    
    def __init__(self, config: SZZConfig):
        self.config = config
        self.use_temp_dir = False
        
    def _convert_project_name(self, project: str) -> str:
        """Convert project name by replacing '/' with '_'"""
        return project.replace("/", "_") if "/" in project else project
    
    def _get_output_paths(self, project: str) -> tuple[str, str]:
        """Get output file and progress file paths"""
        pro_name = self._convert_project_name(project)
        
        if self.config.method == "llm":
            output_file = f"results/{self.config.method}-szz/{self.config.language}/{self.config.model}/{self.config.time}/{self.config.method}-{pro_name}.json"
            progress_file = f"results/{self.config.method}-szz/{self.config.language}/{self.config.model}/{self.config.time}/{self.config.method}-{pro_name}-progress.json"
        else:
            output_file = f"results/{self.config.method}-szz/{self.config.language}/{self.config.time}/{self.config.method}-{pro_name}.json"
            progress_file = f"results/{self.config.method}-szz/{self.config.language}/{self.config.time}/{self.config.method}-{pro_name}-progress.json"
        
        return output_file, progress_file
    
    def _load_existing_output(self, output_file: str) -> Dict[str, Any]:
        """Load existing output from file"""
        if os.path.exists(output_file):
            with open(output_file, 'r') as fin:
                return json.load(fin)
        return {}
    
    def _load_completed_commits(self, progress_file: str) -> List[str]:
        """Load list of completed commits from progress file"""
        if os.path.exists(progress_file):
            with open(progress_file, 'r') as fin:
                return json.load(fin)
        return []
    
    def _save_output(self, output: Dict[str, Any], output_file: str) -> None:
        """Save output to file"""
        with open(output_file, 'w') as fout:
            json.dump(output, fout, indent=4)
    
    def _save_progress(self, completed_commits: List[str], progress_file: str) -> None:
        """Save progress to file"""
        with open(progress_file, 'w') as fout:
            json.dump(completed_commits, fout, indent=4)
    
    def _run_base_szz(self, project: str, commits: List[str], repo_url: Optional[str] = None) -> Dict[str, Any]:
        """Run Base SZZ method"""
        output = {}
        b_szz = BaseSZZ(repo_full_name=project, repo_url=repo_url, repos_dir=REPOS_DIR, use_temp_dir=self.use_temp_dir)
        
        for commit in commits:
            print("==================================================")
            print('Fixing Commit:', commit)
            
            imp_files = b_szz.get_impacted_files(
                fix_commit_hash=commit, 
                file_ext_to_parse=['c', 'java', 'cpp', 'h', 'hpp'], 
                only_deleted_lines=True
            )
            bug_inducing_commits = b_szz.find_bic(
                fix_commit_hash=commit,
                impacted_files=imp_files,
                ignore_revs_file_path=None
            )
            output[commit] = [commit.hexsha for commit in bug_inducing_commits]
        
        return output
    
    def _run_ag_szz(self, project: str, commits: List[str], repo_url: Optional[str] = None) -> Dict[str, Any]:
        """Run AG SZZ method"""
        output = {}
        ag_szz = AGSZZ(repo_full_name=project, repo_url=repo_url, repos_dir=REPOS_DIR, use_temp_dir=self.use_temp_dir)
        
        for commit in commits:
            print('Fixing Commit:', commit)
            
            imp_files = ag_szz.get_impacted_files(
                fix_commit_hash=commit, 
                file_ext_to_parse=['c', 'java', 'cpp', 'h', 'hpp'], 
                only_deleted_lines=True
            )
            bug_inducing_commits = ag_szz.find_bic(
                fix_commit_hash=commit,
                impacted_files=imp_files,
                ignore_revs_file_path=None,
                max_change_size=self.config.max_change_size
            )
            output[commit] = [commit.hexsha for commit in bug_inducing_commits]
        
        return output
    
    def _run_ma_szz(self, project: str, commits: List[str], repo_url: Optional[str] = None) -> Dict[str, Any]:
        """Run MA SZZ method"""
        output = {}
        ma_szz = MASZZ(repo_full_name=project, repo_url=repo_url, repos_dir=REPOS_DIR, use_temp_dir=self.use_temp_dir)
        
        for commit in commits:
            print('Fixing Commit:', commit)
            
            imp_files = ma_szz.get_impacted_files(
                fix_commit_hash=commit, 
                file_ext_to_parse=['c', 'java', 'cpp', 'h', 'hpp'], 
                only_deleted_lines=True
            )
            bug_inducing_commits = ma_szz.find_bic(
                fix_commit_hash=commit,
                impacted_files=imp_files,
                ignore_revs_file_path=None,
                max_change_size=self.config.max_change_size
            )
            output[commit] = [commit.hexsha for commit in bug_inducing_commits]
        
        return output
    
    def _run_v_szz(self, project: str, commits: List[str], repo_url: Optional[str] = None) -> Dict[str, Any]:
        """Run V SZZ method"""
        output = {}
        v_szz = VSZZ(repo_full_name=project, repo_url=repo_url, repos_dir=REPOS_DIR, use_temp_dir=self.use_temp_dir, ast_map_path=AST_MAP_PATH)
        
        for commit in commits:
            print('Fixing Commit:', commit)
            
            imp_files = v_szz.get_impacted_files(
                fix_commit_hash=commit, 
                file_ext_to_parse=['c', 'java', 'cpp', 'h', 'hpp'], 
                only_deleted_lines=True
            )
            bug_inducing_commits = v_szz.find_bic(
                fix_commit_hash=commit,
                impacted_files=imp_files,
                ignore_revs_file_path=None
            )
            output[commit] = bug_inducing_commits
        
        return output
    
    def _run_llm_szz(self, project: str, commits: List[str], repo_url: Optional[str] = None) -> Dict[str, Any]:
        """Run LLM SZZ method"""
        output_file, progress_file = self._get_output_paths(project)
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        output = self._load_existing_output(output_file)
        completed_commits = self._load_completed_commits(progress_file)
        
        use_temp_dir_llm = "/data1/temp/"
        llm_szz = LLMSZZ(
            repo_full_name=project, 
            repo_url=repo_url, 
            repos_dir=REPOS_DIR, 
            use_temp_dir=use_temp_dir_llm, 
            ast_map_path=AST_MAP_PATH,
            model=self.config.model,
            Levenshtein_num=self.config.levenshtein_num
        )
        
        for commit in commits:
            if commit in completed_commits:
                continue
            
            print("================================================== Fixing Commit ==================================================")
            print(commit)
            
            imp_files = llm_szz.get_impacted_files(
                fix_commit_hash=commit, 
                file_ext_to_parse=['c', 'java', 'cpp', 'h', 'hpp'], 
                only_deleted_lines=True
            )
            bug_inducing_commits = llm_szz.find_bic(
                fix_commit_hash=commit,
                impacted_files=imp_files,
                ignore_revs_file_path=None
            )
            output[commit] = bug_inducing_commits
            
            # Save progress after each commit
            self._save_output(output, output_file)
            completed_commits.append(commit)
            self._save_progress(completed_commits, progress_file)
        
        return output
    
    def run_szz(self, project: str, commits: List[str], repo_url: Optional[str] = None) -> None:
        """Main method to run SZZ based on configuration"""
        method_handlers = {
            "b": self._run_base_szz,
            "ag": self._run_ag_szz,
            "ma": self._run_ma_szz,
            "v": self._run_v_szz,
            "llm": self._run_llm_szz
        }
        
        if self.config.method not in method_handlers:
            raise ValueError(f"Unsupported method: {self.config.method}")
        
        output = method_handlers[self.config.method](project, commits, repo_url)
        
        # Save final output for non-LLM methods
        if self.config.method != "llm":
            output_file, _ = self._get_output_paths(project)
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            self._save_output(output, output_file)


class Logger:
    """Logger class to handle output redirection"""
    
    @staticmethod
    def setup_logging(config: SZZConfig) -> None:
        """Setup logging with dual output"""
        if config.method == "llm":
            base_filename = f'results/log/{config.method}-szz__{config.language}__{config.model}__generate-re__log__{config.time}.txt'
        else:
            base_filename = f'results/log/{config.method}-szz__{config.language}__generate-re__log__{config.time}.txt'
        
        mode = 'a' if os.path.exists(base_filename) else 'w'
        sys.stdout = sys.stderr = DualOutput(base_filename, mode)


def print_config(config: SZZConfig) -> None:
    """Print configuration parameters"""
    print(f"Method: {config.method}")
    print(f"Model: {config.model}")
    print(f"Language: {config.language}")
    print(f"Time: {config.time}")
    print(f"Levenshtein_num: {config.levenshtein_num}")


def parse_arguments() -> SZZConfig:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='SZZ Implementation Runner')
    
    parser.add_argument('--method', type=str, default='llm', help='Method to use (default: llm)')
    parser.add_argument('--model', type=str, default='deepseek-chat', help='Model to use (default: deepseek-chat)')
    parser.add_argument('--language', type=str, default='Java', choices=['C', 'Java'], help='Programming language (default: Java)')
    parser.add_argument('--time', type=str, default='x1', help='Time setting (default: x1)')
    parser.add_argument('--levenshtein_num', type=float, default=0.5, help='Levenshtein number (default: 0.5)')
    
    args = parser.parse_args()
    
    return SZZConfig(
        method=args.method,
        model=args.model,
        language=args.language,
        time=args.time,
        levenshtein_num=args.levenshtein_num
    )


def main() -> None:
    """Main function"""
    # Parse arguments and setup configuration
    config = parse_arguments()
    print_config(config)
    
    # Setup logging
    Logger.setup_logging(config)
    
    # Initialize SZZ runner
    runner = SZZRunner(config)
    
    # Load projects and commits
    projects = load_project(config.language)
    project_commits = load_annotated_commits()
    
    # Process each project
    for project in project_commits:
        repo_folder = os.path.join(REPOS_DIR, project)
        
        if not os.path.exists(repo_folder):
            print(f"Skipping {project} as the repository folder does not exist.")
            continue
        
        if project in projects:
            print("Project:", project)
            print("project_commits[project]", project_commits[project])
            
            runner.run_szz(project, project_commits[project])
    
    print("FLUCTUATION:", FLUCTUATION)


if __name__ == "__main__":
    main()

        




        



           





        
                  

                
          
            
        
        
        
    
     
        


        
    