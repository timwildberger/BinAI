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
TMPDIR=$(mktemp -d /scratch/binai_XXXXXX)

ERROR_LOG="$SLURM_DIR/error.log"

# Ensure slurm log directory exists
mkdir -p "$SLURM_DIR"

# Copy project to compute node (exclude slurm logs)
echo "Copying repo to compute node scratch directory..."
rsync -a --exclude slurm "$REPO_ROOT/" "$TMPDIR/"

# Activate Python environment
source "$PYENV_ROOT/bin/activate" && echo "pyenv loaded"

# Run the job
cd "$TMPDIR"
PYTHON_SCRIPT="$TMPDIR/preproc/decompiler_mult.py"

echo "Running Python job in scratch directory..."
srun --ntasks 1 --nodes=1 -c 14 python3 "$PYTHON_SCRIPT" > "$TMPDIR/output.txt" 2> "$TMPDIR/error.log"

# Sync output back to submit node
OUT_DIR="$REPO_ROOT/out"
echo "Syncing 'out' folder back to submit node..."
rsync -a "$TMPDIR/out/" "$OUT_DIR/"

# Sync logs
cp "$TMPDIR/output.txt" "$SLURM_DIR/output.txt"
cp "$TMPDIR/error.log" "$ERROR_LOG"

# Timestamp for zip name
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
ZIP_PATH="$SLURM_DIR/output_$TIMESTAMP.zip"
zip -r "$ZIP_PATH" "$OUT_DIR" "$SLURM_DIR"

# Prepare email body
EMAIL_BODY="$SLURM_DIR/email_body.txt"
if [ -s "$ERROR_LOG" ]; then
    echo "Job completed with errors. See the error trace below:" > "$EMAIL_BODY"
    cat "$ERROR_LOG" >> "$EMAIL_BODY"
else
    echo "Job completed successfully." > "$EMAIL_BODY"
    echo "" >> "$EMAIL_BODY"
    echo "Output files have been saved to: $OUT_DIR" >> "$EMAIL_BODY"
    echo "" >> "$EMAIL_BODY"
    echo "Standard output follows:" >> "$EMAIL_BODY"
    echo "-------------------------" >> "$EMAIL_BODY"
    cat "$SLURM_DIR/output.txt" >> "$EMAIL_BODY"
fi

# Attach output zip and send email
echo "Sending email with results..."
echo "Please find the job results and any error messages below." | \
mutt -s "BinAI Job results" -a "$ZIP_PATH" -i "$EMAIL_BODY" -- "$MAIL_USER"

# Cleanup
echo "Cleaning up temporary directory: $TMPDIR"
rm -rf "$TMPDIR"

echo "Slurm execution done."
