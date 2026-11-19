import os
import zipfile
import time

WORKSPACE = r"c:\Users\Purnendu\Downloads\attack-detective"
ZIP_OUT = r"c:\Users\Purnendu\Downloads\attack-detective\Attack_Detective_Project.zip"

# Items to explicitly include
INCLUDE_DIRS = [
    "src",
    "web_dashboard",
    "scripts",
    "tests",
    "tools",
    "demo_csv_samples",
    "results",
    "results_demo",
    "artifacts",
    "artifacts_demo"
]

INCLUDE_FILES = [
    "Attack_Detective_Evaluation_Tables.pdf",
    "Attack_Detective_Report_Appendix.pdf",
    "report_tables.html",
    "config.yaml",
    "requirements.txt",
    "run_all.py",
    "build_appendix_pdf.py",
    "build_full_pdf_reportlab.py",
    "generate_report_pdf.py",
    ".gitignore",
    "README.txt"
]

EXCLUDE_PATTERNS = [
    "__pycache__",
    ".pyc",
    ".pytest_cache",
    ".venv",
    ".edge_temp",
    ".mpl_temp",
    "math_img",
    "Crashpad",
    "Default",
    "GPUPersistentCache",
    "Attack_Detective_Project.zip"
]

def should_exclude(rel_path):
    for pattern in EXCLUDE_PATTERNS:
        if pattern in rel_path.replace("\\", "/").split("/"):
            return True
        if rel_path.endswith(pattern):
            return True
    return False

def make_zip():
    start_time = time.time()
    total_files = 0
    total_uncompressed_bytes = 0

    print("Creating Attack_Detective_Project.zip ...")
    with zipfile.ZipFile(ZIP_OUT, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zipf:
        # 1. Add explicitly included single files in root
        for f in INCLUDE_FILES:
            full_path = os.path.join(WORKSPACE, f)
            if os.path.exists(full_path):
                zipf.write(full_path, arcname=f)
                size = os.path.getsize(full_path)
                total_uncompressed_bytes += size
                total_files += 1
                print(f"  + Added root file: {f} ({size:,} bytes)")

        # 2. Add explicitly included directories
        for d in INCLUDE_DIRS:
            dir_full = os.path.join(WORKSPACE, d)
            if not os.path.exists(dir_full):
                continue
            for root, dirs, files in os.walk(dir_full):
                # Filter out excluded subdirs in-place
                dirs[:] = [d_name for d_name in dirs if not should_exclude(os.path.join(root, d_name))]
                for file in files:
                    full_p = os.path.join(root, file)
                    rel_p = os.path.relpath(full_p, WORKSPACE)
                    if should_exclude(rel_p):
                        continue
                    zipf.write(full_p, arcname=rel_p)
                    size = os.path.getsize(full_p)
                    total_uncompressed_bytes += size
                    total_files += 1

    zip_size = os.path.getsize(ZIP_OUT)
    duration = time.time() - start_time
    print(f"\nSuccessfully created {ZIP_OUT}")
    print(f"Total files packaged: {total_files}")
    print(f"Uncompressed size: {total_uncompressed_bytes / (1024*1024):.2f} MB")
    print(f"Compressed ZIP size: {zip_size / (1024*1024):.2f} MB")
    print(f"Time taken: {duration:.2f} seconds")

if __name__ == "__main__":
    make_zip()
