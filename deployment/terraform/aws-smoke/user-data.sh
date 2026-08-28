#!/bin/bash
set -euo pipefail

systemctl enable --now amazon-ssm-agent
install -d -m 0755 -o ec2-user -g ec2-user /opt/rladkr
install -d -m 0755 -o ec2-user -g ec2-user /opt/rladkr/bin
install -d -m 0755 -o ec2-user -g ec2-user /etc/rladkr
install -d -m 0755 -o ec2-user -g ec2-user /var/log/rladkr
install -d -m 0755 -o ec2-user -g ec2-user /var/lib/rladkr/artifacts
