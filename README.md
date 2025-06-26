# LLM-SZZ: Replication Package

This repository contains the replication materials for the paper:

**"LLM-SZZ: Novel Vulnerability Affected Range Identification Driven by Large Language Model and CVE Description"**

---

## 📁 Main Directory

* `data/`
  Contains datasets and annotations:

  * `c_cve_fix_detail.json` / `java_cve_fix_detail.json`: Vulnerability-fixing commits for C/C++ and Java projects.
  * `label.json`: Manually annotated CVEs with their inducing and descendant commits.
  * `verified_cve_with_versions_C.json` / `verified_cve_with_versions_Java.json`: CVEs with version metadata, associated fixing commits, inducing commits, and predicted vulnerable versions.

* `SZZ/`
  Contains implementations of various SZZ algorithms:

  * `llm_szz.py`: Our proposed LLM-SZZ algorithm.
  * Implementations by Rosa et al. (ICSE 2021) and Bao et al. (V-SZZ) are also included.

---

## 🚀 Getting Started

### 0. Environment Setup

It is recommended to use a Python virtual environment (venv) to avoid dependency conflicts:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

### 1. Data Preparation

* Download repositories associated with CVEs by running:

  > **Note:** Before running, make sure to update `WORK_DIR` and `REPOS_DIR` in `setting.py` to the correct paths for your environment.

  ```bash
  python download_repos.py
  ```

* Download the official CVE metadata:

  * Clone the repository [cvelistV5](https://github.com/CVEProject/cvelistV5) and place it in the directory:

    ```
    ./cvelistV5-main/
    ```

---

### 2. Running SZZ Algorithms

* Configure the SZZ algorithm in `run.sh`:

  ```python
  METHOD = 'llm'  # Options: b, ag, ma, v, llm
  ```

  * `b`: B-SZZ
  * `ag`: AG-SZZ
  * `ma`: MA-SZZ
  * `v`: V-SZZ
  * `llm`: LLM-SZZ (ours)

* Set the LLM model in `run.sh`:

  ```python
  MODEL = 'gpt-4o-2024-05-13'  # Example
  ```


  **Note**: Add your API key in `SZZ/szz/core/llm.py`.

* To run the main SZZ pipeline:

  ```bash
  . run.sh
  ```

---

### 3. Evaluation

* Evaluate the performance of different SZZ methods:

  ```bash
  python evaluate.py --method "llm" --language "Java" --time "01" --model "gpt-3.5-turbo-0125"
  ```

---

## 📜 Citation

If you use the code, please cite our paper.

---

