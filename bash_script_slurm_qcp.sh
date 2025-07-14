#!/usr/bin/env bash
#SBATCH --job-name=binai
#SBATCH --comment="Binary Disassembly"
#SBATCH --mail-type=ALL
#SBATCH --mail-user=tim.wildberger@campus.lmu.de
#SBATCH --partition=All
#SBATCH --nodes=1
#SBATCH -B 1:7:2
#SBATCH -n 1

# -------- DYNAMIC CONFIGURATION ------- #
SKIP_EXISTING="$1"  # Pass 1 to enable --skip_existing

# -------- Static Configuration -------- #
MAIL_USER="tim.wildberger@campus.lmu.de"
REPO_ROOT="$SLURM_SUBMIT_DIR"
SLURM_DIR="$REPO_ROOT/slurm"
OUT_DIR="$REPO_ROOT/out"
QUEUE_DIR="$REPO_ROOT/queue"

mkdir -p "$SLURM_DIR" "$OUT_DIR" "$QUEUE_DIR"

ERROR_LOG="$SLURM_DIR/error.log"
OUTPUT_LOG="$SLURM_DIR/output.txt"

source "$REPO_ROOT/.venv/bin/activate"

# -------- Node count (runtime configurable) -------- #
if [[ -n "$NODES" ]]; then
    NUM_NODES="$NODES"
    echo "Using user-defined number of nodes: $NUM_NODES"
else
    NUM_NODES=4
    echo "No node count specified. Falling back to default: $NUM_NODES node(s)."
fi

if [[ "$NUM_NODES" -lt 1 ]]; then
    echo "Invalid node count: $NUM_NODES. Must be >= 1. Exiting."
    exit 1
fi

# -------- Step 1: Generate queue files -------- #
echo "Generating $NUM_NODES queue files using binary_filter.py..."
python3 "$REPO_ROOT/preproc/binary_filter.py" --splits "$NUM_NODES" --output-dir "$QUEUE_DIR"

# -------- Step 2: Submit jobs for each queue file -------- #
echo "Submitting jobs for each queue file..."
DEPENDENCIES=()

for QUEUE_FILE in "$QUEUE_DIR"/*.txt; do
    BASENAME=$(basename "$QUEUE_FILE" .txt)
    JOB_ID=$(sbatch --parsable --export=ALL,SKIP_EXISTING=$SKIP_EXISTING,QUEUE_FILE="$QUEUE_FILE",REPO_ROOT="$REPO_ROOT",SLURM_DIR="$SLURM_DIR" <<EOF
#!/bin/bash
#SBATCH --job-name=binai-${BASENAME}
#SBATCH --output=${SLURM_DIR}/slurm_%x.out
#SBATCH --error=${SLURM_DIR}/slurm_%x.err
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=14
#SBATCH --partition=All
#SBATCH --comment="Process queue file"

source "\${REPO_ROOT}/.venv/bin/activate"
cd "\${REPO_ROOT}"

NUM_CPUS=\$((SLURM_CPUS_PER_TASK - 1))
echo "Launching \$NUM_CPUS workers for \${QUEUE_FILE} with SKIP_EXISTING=\${SKIP_EXISTING}"

for i in \$(seq 1 \$NUM_CPUS); do
    if [[ "\${SKIP_EXISTING}" == "1" ]]; then
        python3 -m tokenizer.low_level --batch "\${QUEUE_FILE}" --skip_existing &
    else
        python3 -m tokenizer.low_level --batch "\${QUEUE_FILE}" &
    fi
done

wait
echo "All workers completed for \${QUEUE_FILE}"
EOF
)
    echo "Submitted job $JOB_ID for $QUEUE_FILE"
    DEPENDENCIES+=($JOB_ID)
done

# -------- Optional: Final notification -------- #
DEPENDENCY_STRING=$(IFS=:; echo "${DEPENDENCIES[*]}")
sbatch --dependency=afterok:$DEPENDENCY_STRING --job-name=binai-notify <<EOF
#!/bin/bash
#SBATCH --output=${SLURM_DIR}/slurm_notify.out
#SBATCH --error=${SLURM_DIR}/slurm_notify.err
#SBATCH --ntasks=1
#SBATCH --time=00:01:00
#SBATCH --partition=All

echo "All child SLURM jobs completed for binai." | mail -s "binai job complete" ${MAIL_USER}
EOF

echo "All subjobs submitted. Final notification job scheduled."
