# Scoutnet Deployment Guide

## System Overview
The distributed Honeynet consists of two components:
1. Central C2 Server (c2.zig): Collects and processes intrusion attempt reports
2. Scout Nodes (scout.zig): Lightweight sensors that monitor for connection attempts

## Prerequisites
- Azure Subscription with Contributor access
- Azure CLI installed and configured
- Zig compiler (version 0.13.0 or later)
- Linux build environment

## C2 Server Deployment

### Infrastructure Setup
```bash
# Create resource group
az group create --name rg-honeynet-prod --location eastus2

# Create dedicated VNET
az network vnet create \
  --name vnet-honeynet \
  --resource-group rg-honeynet-prod \
  --address-prefix 10.0.0.0/16 \
  --subnet-name snet-c2 \
  --subnet-prefix 10.0.1.0/24

# Create NSG for C2 server
az network nsg create \
  --name nsg-c2 \
  --resource-group rg-honeynet-prod

# Allow inbound traffic only from scout subnets
az network nsg rule create \
  --name allow-scouts \
  --nsg-name nsg-c2 \
  --priority 100 \
  --resource-group rg-honeynet-prod \
  --access Allow \
  --destination-port-ranges 8080 \
  --direction Inbound \
  --protocol Tcp
```

### C2 Server VM Deployment
```bash
# Create C2 server VM
az vm create \
  --resource-group rg-honeynet-prod \
  --name vm-c2-prod \
  --image Ubuntu2204 \
  --size Standard_B2s \
  --admin-username azureuser \
  --generate-ssh-keys \
  --vnet-name vnet-honeynet \
  --subnet snet-c2 \
  --nsg nsg-c2

# Configure VM
az vm run-command invoke \
  --resource-group rg-honeynet-prod \
  --name vm-c2-prod \
  --command-id RunShellScript \
  --scripts "apt-get update && apt-get install -y build-essential"
```

### Application Deployment
```bash
# Install Zig 0.13.0
sudo apt update && \ 
sudo apt install -y curl xz-utils build-essential && \
curl -O https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz && \
tar xf zig-linux-x86_64-0.13.0.tar.xz && \
sudo mv zig-linux-x86_64-0.13.0 /usr/local/zig && \
sudo ln -s /usr/local/zig/zig /usr/local/bin/zig && \
zig version

# Compile C2 server
zig build-exe c2.zig -O ReleaseSafe

# Create systemd service
sudo vi /etc/systemd/system/c2-server.service
```

Paste this into the service file
```
[Unit]
Description=C2 Server Service
After=network.target

[Service]
Type=simple
User=azureuser
ExecStart=/home/azureuser/c2
WorkingDirectory=/home/azureuser
Restart=always
RestartSec=5
StandardOutput=append:/var/log/c2-server.log
StandardError=append:/var/log/c2-server.log

[Install]
WantedBy=multi-user.target
```
```
# Create log file with proper permissions
sudo touch /var/log/c2-server.log
sudo chown azureuser:azureuser /var/log/c2-server.log

# Start service
systemctl daemon-reload
systemctl enable c2-server.service
systemctl start c2-server.service
```

## Scout Node Deployment

### Infrastructure Setup
```bash
# Create scout subnet
az network vnet subnet create \
  --name snet-scouts \
  --resource-group rg-honeynet-prod \
  --vnet-name vnet-honeynet \
  --address-prefix 10.0.2.0/24

# Create NSG for scouts
az network nsg create \
  --name nsg-scouts \
  --resource-group rg-honeynet-prod

# Allow monitored ports
az network nsg rule create \
  --name allow-honeypot-ports \
  --nsg-name nsg-scouts \
  --priority 100 \
  --resource-group rg-honeynet-prod \
  --access Allow \
  --destination-port-ranges 22 23 3389 \
  --direction Inbound \
  --protocol Tcp
```

### Scout VM Deployment
```bash
# Create scout VM (repeat for each scout)
az vm create \
  --resource-group rg-honeynet-prod \
  --name vm-scout-001 \
  --image Ubuntu2204 \
  --size Standard_B1s \
  --admin-username azureuser \
  --generate-ssh-keys \
  --vnet-name vnet-honeynet \
  --subnet snet-scouts \
  --nsg nsg-scouts
```

### Application Deployment
```bash
# Install Zig 0.13.0
sudo apt update && \ 
sudo apt install -y curl xz-utils build-essential && \
curl -O https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz && \
tar xf zig-linux-x86_64-0.13.0.tar.xz && \
sudo mv zig-linux-x86_64-0.13.0 /usr/local/zig && \
sudo ln -s /usr/local/zig/zig /usr/local/bin/zig && \
zig version

# Compile scout
zig build-exe scout.zig -O ReleaseSafe

# Create systemd service
sudo vi /etc/systemd/system/scout.service
```
Paste this into the service file
```
[Unit]
Description=Scout Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/home/azureuser/scout
WorkingDirectory=/home/azureuser
Restart=always
RestartSec=5
StandardOutput=append:/var/log/scout.log
StandardError=append:/var/log/scout.log

[Install]
WantedBy=multi-user.target
```
```
# Create log file with proper permissions
sudo touch /var/log/scout.log
sudo chown root:root /var/log/scout.log

# Start service
systemctl daemon-reload
systemctl enable honeynet-scout
systemctl start honeynet-scout
```
## Monitor
```
# Monitor C2 server reports
tail -f /home/azureuser/c2_reports.log

# Monitor scout reports
tail -f /home/azureuser/scout_reports.log
```

## Maintenance
- Regularly update Ubuntu packages
- Monitor VM metrics and logs
