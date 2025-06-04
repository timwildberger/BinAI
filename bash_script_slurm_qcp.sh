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

# Set directory where SLURM job was submitted from
REPO_ROOT="$SLURM_SUBMIT_DIR"
SLURM_DIR="$REPO_ROOT/slurm"
TMPDIR=$(mktemp -d /scratch/binai_XXXXXX)

ERROR_LOG="$SLURM_DIR/error.log"

# Create the slurm directory on the submission node
mkdir -p "$SLURM_DIR"

# Copy project files to temp directory on compute node
echo "Copying repo to compute node scratch directory..."
rsync -a --exclude slurm "$REPO_ROOT/" "$TMPDIR/"

# Activate Python environment
source "$PYENV_ROOT/bin/activate" && echo "pyenv loaded"

# Run the Python job in the temp directory
cd "$TMPDIR"
PYTHON_SCRIPT="$TMPDIR/preproc/decompiler_mult.py"

echo "Running Python job in scratch directory..."
srun --ntasks 1 --nodes=1 -c 14 python3 "$PYTHON_SCRIPT" > "$TMPDIR/output.txt" 2> "$TMPDIR/error.log"

# Copy output directory back to the original repo on the submission node
echo "Syncing 'out' folder back to submit node..."
rsync -a "$TMPDIR/out/" "$REPO_ROOT/out/"

# Copy logs back
cp "$TMPDIR/output.txt" "$SLURM_DIR/output.txt"
cp "$TMPDIR/error.log" "$ERROR_LOG"

# Build email body based on success/failure
if [ -s "$ERROR_LOG" ]; then
    echo "Job completed with errors. See the error trace below:" > "$SLURM_DIR/email_body.txt"
    cat "$ERROR_LOG" >> "$SLURM_DIR/email_body.txt"
else
    echo "Job completed successfully. See the output below:" > "$SLURM_DIR/email_body.txt"
    cat "$SLURM_DIR/output.txt" >> "$SLURM_DIR/email_body.txt"
fi

# Timestamp and zip
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
mv *.out "$SLURM_DIR" 2>/dev/null
zip -r "$SLURM_DIR/output_$TIMESTAMP.zip" "$SLURM_DIR"

# Email results
echo "Sending email with results..."
echo "Please find the job results and any error messages below." | mutt -s "BinAI Job results" -a "$SLURM_DIR/output_$TIMESTAMP.zip" -i "$SLURM_DIR/email_body.txt" -- "$MAIL_USER"

echo "Cleaning up temporary directory: $TMPDIR"
rm -rf "$TMPDIR"

echo "Slurm execution done."
