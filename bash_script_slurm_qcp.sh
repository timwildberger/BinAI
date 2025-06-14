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

REPO_ROOT="$SLURM_SUBMIT_DIR"
SLURM_DIR="$REPO_ROOT/slurm"
OUT_DIR="$REPO_ROOT/out"
QUEUE_DIR="$REPO_ROOT/queue"

mkdir -p "$SLURM_DIR" "$OUT_DIR" "$QUEUE_DIR"

ERROR_LOG="$SLURM_DIR/error.log"
OUTPUT_LOG="$SLURM_DIR/output.txt"

source "$REPO_ROOT/.venv/bin/activate"

# Step 1: Determine number of available nodes (idle nodes in 'All' partition)
echo "Detecting available nodes..."
NUM_NODES=$(sinfo -h -p All -o "%D" | awk '{s+=$1} END {print s}')
echo "Detected $NUM_NODES available node(s)."

if [[ -z "$NUM_NODES" || "$NUM_NODES" -lt 1 ]]; then
    echo "No available nodes detected. Exiting."
    exit 1
fi

# Step 2: Run binary_filter.py with number of splits
echo "Generating $NUM_NODES queue files using binary_filter.py..."
python3 "$REPO_ROOT/preproc/binary_filter.py" --splits "$NUM_NODES" --output-dir "$QUEUE_DIR"

# Step 3: Submit one job per queue file
echo "Submitting jobs for each queue file..."

DEPENDENCIES=()

for QUEUE_FILE in "$QUEUE_DIR"/*.txt; do
    BASENAME=$(basename "$QUEUE_FILE" .txt)
    JOB_ID=$(sbatch --parsable <<EOF
#!/usr/bin/env bash
#SBATCH --job-name=binai-$BASENAME
#SBATCH --output=$SLURM_DIR/slurm_%x.out
#SBATCH --error=$SLURM_DIR/slurm_%x.err
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=14
#SBATCH --partition=All
#SBATCH --comment="Process queue file $QUEUE_FILE"

source "$REPO_ROOT/.venv/bin/activate"
cd "$REPO_ROOT"
python3 preproc/decompiler_mult.py "$QUEUE_FILE"
EOF
)
    echo "Submitted job $JOB_ID for $QUEUE_FILE"
    DEPENDENCIES+=($JOB_ID)
done

# Step 4: Final notification job
DEPENDENCY_STRING=$(IFS=:; echo "${DEPENDENCIES[*]}")
sbatch --dependency=afterok:$DEPENDENCY_STRING --job-name=binai-notify <<EOF
#!/usr/bin/env bash
#SBATCH --output=$SLURM_DIR/slurm_notify.out
#SBATCH --error=$SLURM_DIR/slurm_notify.err
#SBATCH --ntasks=1
#SBATCH --time=00:01:00
#SBATCH --partition=All

echo "All child SLURM jobs completed for binai." | mail -s "binai job complete" $MAIL_USER
EOF

echo "All subjobs submitted. Final notification job scheduled."
