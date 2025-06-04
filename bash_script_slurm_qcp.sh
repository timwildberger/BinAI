#!/usr/bin/env bash
#SBATCH --job-name=binai
#SBATCH --comment="Binary Disassembly"
#SBATCH --mail-type=ALL
#SBATCH --mail-user=tim.wildberger@campus.lmu.de
#SBATCH --partition=All
#SBATCH --nodes=1
#SBATCH -B 1:7:2
#SBATCH -n 1

MAIL_USER="tim.wildberger@campus.lmu.de"

# Directory where job was submitted from
REPO_ROOT="$SLURM_SUBMIT_DIR"
SLURM_DIR="$REPO_ROOT/slurm"
OUT_DIR="$REPO_ROOT/out"
QUEUE_DIR="$REPO_ROOT/queue"

# Ensure directories exist
mkdir -p "$SLURM_DIR" "$OUT_DIR" "$QUEUE_DIR"

ERROR_LOG="$SLURM_DIR/error.log"
OUTPUT_LOG="$SLURM_DIR/output.txt"

# Activate Python environment
source "$REPO_ROOT/.venv/bin/activate"

# Step 1: Run binary_filter.py to populate queue/
echo "Running binary_filter.py to generate queue files..."
python3 "$REPO_ROOT/preproc/binary_filter.py"

# Step 2: Launch separate jobs for each queue file
echo "Submitting jobs for each queue file..."
for QUEUE_FILE in "$QUEUE_DIR"/*.txt; do
    BASENAME=$(basename "$QUEUE_FILE" .txt)
    sbatch <<EOF
#!/usr/bin/env bash
#SBATCH --job-name=binai-$BASENAME
#SBATCH --output=$SLURM_DIR/slurm_%x.out
#SBATCH --error=$SLURM_DIR/slurm_%x.err
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=14
#SBATCH --partition=All
#SBATCH --comment="Process queue file $QUEUE_FILE"

source "$PYENV_ROOT/bin/activate"
cd "$REPO_ROOT"
python3 preproc/decompiler_mult.py "$QUEUE_FILE"
EOF
done

# Done with main submission script
echo "All subjobs submitted."

