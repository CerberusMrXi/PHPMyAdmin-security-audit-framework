#!/bin/bash
# Setup script for PHPMyAdmin Security Framework

echo "Setting up PHPMyAdmin Security Assessment Framework v1.0"

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
mkdir -p reports logs configs

# Copy example configuration
if [ ! -f configs/config.yaml ]; then
    cat > configs/config.yaml <<EOF
# Default configuration
enabled_plugins: all
timeout: 30
max_connections: 10
retries: 3
output_dir: reports
log_level: INFO
EOF
    echo "Created default configuration"
fi

# Make scripts executable
chmod +x pma_audit.py

echo "Setup complete!"
echo "Run: python pma_audit.py https://example.com/phpmyadmin"
