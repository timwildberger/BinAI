#!/usr/bin/env bash
#SBATCH --job-name=qcp-train-routing
#SBATCH --comment="Solving time delays for the Deutsche Bahn"
#SBATCH --mail-type=ALL
#SBATCH --mail-user=tim.wildberger@campus.lmu.de
#SBATCH --partition=All
#SBATCH --nodes 1
#SBATCH -B 1:7:2
#SBATCH -n 1


# Control variable to set the email recipient ('T' for Tim, 'J' for Friedrich)
EMAIL_RECIPIENT="T"

# Set the recipient based on EMAIL_RECIPIENT variable
if [ "$EMAIL_RECIPIENT" == "T" ]; then
    MAIL_USER="tim.wildberger@campus.lmu.de"
elif [ "$EMAIL_RECIPIENT" == "J" ]; then
    MAIL_USER="j.friedrich@campus.lmu.de"
else
    echo "Invalid EMAIL_RECIPIENT value. Please set it to 'T' or 'J'."
    exit 1
fi

SLURM_DIR="slurm"
ERROR_LOG="$SLURM_DIR/error.log"  # Error log file in the slurm folder

# Create the slurm directory if it doesn't exist
mkdir -p $SLURM_DIR

# Activate python environment
source "$PYENV_ROOT/bin/activate" && echo "pyenv loaded"

# Absolute path to the Python script (ensure it is correct)
PYTHON_SCRIPT="$HOME/Desktop/qcp/siemens-train-routing/model/lr/lr_pipeline.py"

# Run the python job and capture both stdout and stderr inside the slurm folder
echo "Running Python job and capturing output and error..."
srun --ntasks 1 --nodes=1 -c 14 python3 "$PYTHON_SCRIPT" > "$SLURM_DIR/output.txt" 2> "$ERROR_LOG"

# Check if any error occurred and store it in the error log and email body
echo "Checking for errors in the error log..."
# Ensure the error file has content
if [ -s "$ERROR_LOG" ]; then
    #If error log has content, include it in the email body
    echo "Job completed with errors. See the error trace below:" > "$SLURM_DIR/email_body.txt"
    cat "$ERROR_LOG" >> "$SLURM_DIR/email_body.txt"
else
    # If no errors, simply notify success
    echo "Job completed successfully. See the output below:" > "$SLURM_DIR/email_body.txt"
    cat "$SLURM_DIR/output.txt" >> "$SLURM_DIR/email_body.txt"
fi

# Create a timestamp
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")

# Move all output files to the slurm folder
echo "Moving .out files to SLURM_DIR"
mv *.out "$SLURM_DIR"

# Create a zip file with a timestamp
zip -r "$SLURM_DIR/output_$TIMESTAMP.zip" "$SLURM_DIR"

# Send the results via email with the zip file attached
echo "Sending email with very nice results."

# The '-i' flag points to the email body file and '-a' attaches the zip file
echo "Please find the job results and any error messages below." | mutt -s "QCP Train Routing Results" -a "$SLURM_DIR/output_$TIMESTAMP.zip" -i "$SLURM_DIR/email_body.txt" -- "$MAIL_USER"

echo "Slurm execution done."
