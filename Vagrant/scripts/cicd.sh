#! /bin/bash
# Bachelorproef: CRA-compliance door CI/CD-pipelines
# CICD Server adhv. Jenkins

# update & upgrade
apt update && apt upgrade -y

# install Docker (Debian/Ubuntu)
apt install -y docker.io curl
echo "enabling Docker service"
systemctl enable --now docker

# optionally add the vagrant user to docker group so sudo is not required
usermod -aG docker vagrant

# prepare Jenkins home directory
mkdir -p /var/jenkins_home
chown 1000:1000 /var/jenkins_home

# pull the latest Jenkins LTS image
docker pull jenkins/jenkins:lts

# run Jenkins in a container if not already running
if ! docker ps --format '{{.Names}}' | grep -q '^jenkins$'; then
    docker run -d --name jenkins \
        -p 8080:8080 -p 50000:50000 \
        -v /var/jenkins_home:/var/jenkins_home \
        --restart=unless-stopped \
        jenkins/jenkins:lts
else
    echo "Jenkins container already running"
fi