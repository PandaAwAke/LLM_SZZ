import os
import logging
import json
import sys
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass
from git import Repo
from git.exc import GitCommandError

from setting import *
from data_loader import load_annotated_commits


@dataclass
class DownloadResult:
    """Data class to store download operation results."""
    project_name: str
    success: bool
    repo_path: Optional[str] = None
    error_message: Optional[str] = None


class RepositoryDownloader:
    """
    A class to handle repository downloading operations with proper error handling
    and logging.
    """
    
    def __init__(self, repos_dir: str, config_files: List[str]):
        """
        Initialize the RepositoryDownloader.
        
        Args:
            repos_dir: Directory where repositories will be downloaded
            config_files: List of JSON configuration files containing project URLs
        """
        self.repos_dir = Path(repos_dir)
        self.config_files = [Path(f) for f in config_files]
        self.logger = self._setup_logger()
        self.project_urls: Dict[str, str] = {}
        
    def _setup_logger(self) -> logging.Logger:
        """Set up logging configuration."""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        
        # Create console handler if not already exists
        if not logger.handlers:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            
            # Create formatter
            formatter = logging.Formatter(
                '%(asctime)s :: %(name)s :: %(levelname)s :: %(message)s'
            )
            console_handler.setFormatter(formatter)
            
            # Add handler to logger
            logger.addHandler(console_handler)
        
        # Set git logger to warning level to reduce noise
        logging.getLogger('git').setLevel(logging.WARNING)
        
        return logger
    
    def load_project_urls(self, output_file: str) -> Dict[str, str]:
        """
        Load project URLs from configuration files.
        
        Args:
            output_file: Path to save consolidated URL information
            
        Returns:
            Dictionary mapping project names to their URLs
        """
        self.logger.info("Loading project URLs from configuration files...")
        
        all_urls = {}
        
        for config_file in self.config_files:
            if not config_file.exists():
                self.logger.warning(f"Configuration file not found: {config_file}")
                continue
                
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                for project, project_info in data.items():
                    url = project_info.get('url', 'N/A')
                    if url != 'N/A':
                        all_urls[project] = url
                        
            except (json.JSONDecodeError, IOError) as e:
                self.logger.error(f"Error reading configuration file {config_file}: {e}")
                continue
        
        # Save consolidated URLs
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(all_urls, f, indent=2)
            self.logger.info(f"Project URLs saved to: {output_file}")
        except IOError as e:
            self.logger.error(f"Error saving URL information: {e}")
        
        self.project_urls = all_urls
        return all_urls
    
    def download_repository(self, project_name: str) -> DownloadResult:
        """
        Download a single repository.
        
        Args:
            project_name: Name of the project to download
            
        Returns:
            DownloadResult object containing operation status
        """
        if project_name not in self.project_urls:
            return DownloadResult(
                project_name=project_name,
                success=False,
                error_message="Project URL not found in configuration"
            )
        
        repo_url = self.project_urls[project_name]
        repo_path = self.repos_dir / project_name
        
        # Check if repository already exists
        if repo_path.exists():
            self.logger.info(f"Repository {project_name} already exists at {repo_path}")
            return DownloadResult(
                project_name=project_name,
                success=True,
                repo_path=str(repo_path)
            )
        
        self.logger.info(f"Downloading repository {project_name} from {repo_url}")
        
        try:
            # Create parent directory if it doesn't exist
            repo_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Clone repository
            Repo.clone_from(repo_url, repo_path)
            
            self.logger.info(f"Successfully downloaded {project_name} to {repo_path}")
            return DownloadResult(
                project_name=project_name,
                success=True,
                repo_path=str(repo_path)
            )
            
        except GitCommandError as e:
            error_msg = f"Git command error: {e}"
            self.logger.error(f"Failed to download {project_name}: {error_msg}")
            return DownloadResult(
                project_name=project_name,
                success=False,
                error_message=error_msg
            )
        except Exception as e:
            error_msg = f"Unexpected error: {e}"
            self.logger.error(f"Failed to download {project_name}: {error_msg}")
            return DownloadResult(
                project_name=project_name,
                success=False,
                error_message=error_msg
            )
    
    def download_all_repositories(self, project_list: List[str]) -> Tuple[List[str], List[str]]:
        """
        Download all repositories in the project list.
        
        Args:
            project_list: List of project names to download
            
        Returns:
            Tuple of (successful_downloads, failed_downloads)
        """
        self.logger.info(f"Starting download of {len(project_list)} repositories...")
        
        successful_downloads = []
        failed_downloads = []
        
        for i, project in enumerate(project_list, 1):
            self.logger.info(f"Processing project {i}/{len(project_list)}: {project}")
            
            result = self.download_repository(project)
            
            if result.success:
                successful_downloads.append(project)
            else:
                failed_downloads.append(project)
                self.logger.warning(f"Failed to download {project}: {result.error_message}")
        
        return successful_downloads, failed_downloads
    
    def print_summary(self, successful_downloads: List[str], failed_downloads: List[str]) -> None:
        """
        Print a summary of the download operation.
        
        Args:
            successful_downloads: List of successfully downloaded projects
            failed_downloads: List of failed downloads
        """
        total = len(successful_downloads) + len(failed_downloads)
        
        self.logger.info("=" * 50)
        self.logger.info("DOWNLOAD SUMMARY")
        self.logger.info("=" * 50)
        self.logger.info(f"Total projects processed: {total}")
        self.logger.info(f"Successfully downloaded: {len(successful_downloads)}")
        self.logger.info(f"Failed downloads: {len(failed_downloads)}")
        self.logger.info(f"Success rate: {(len(successful_downloads)/total)*100:.1f}%")
        
        if successful_downloads:
            self.logger.info(f"Successful downloads: {', '.join(successful_downloads)}")
        
        if failed_downloads:
            self.logger.warning(f"Failed downloads: {', '.join(failed_downloads)}")


def main():
    """Main function to orchestrate the repository download process."""
    try:
        # Load project commits
        project_commits = load_annotated_commits()
        
        # Configuration
        config_files = [
            os.path.join(DATA_FOLDER, 'c_cve_fix_detail.json'),
            os.path.join(DATA_FOLDER, 'java_cve_fix_detail.json')
        ]
        output_file = os.path.join(DATA_FOLDER, 'repo_details.json')
        
        # Initialize downloader
        downloader = RepositoryDownloader(REPOS_DIR, config_files)
        
        # Load project URLs
        project_urls = downloader.load_project_urls(output_file)
        
        # Get list of projects to download
        projects_to_download = list(project_commits.keys())
        
        # Download all repositories
        successful_downloads, failed_downloads = downloader.download_all_repositories(
            projects_to_download
        )
        
        # Print summary
        downloader.print_summary(successful_downloads, failed_downloads)
        
        # Exit with error code if any downloads failed
        if failed_downloads:
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nDownload process interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()


