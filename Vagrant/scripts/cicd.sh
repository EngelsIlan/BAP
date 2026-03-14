#! /bin/bash
# Bachelorproef: CRA-compliance door CI/CD-pipelines
# CICD Server adhv. Jenkins
# Jenkins password:
# 6bfdc7175dc04dd88368edc03277a0c8
# update & upgrade
apt update && apt upgrade -y

# Requirements:
apt install zip unzip -y

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
    docker run -p 8080:8080 -u root \
        -v jenkins-data:/var/jenkins_home \
        -v $(which docker):/usr/bin/docker \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$HOME":/home \
        --name jenkins_server jenkins/jenkins:lts
else
    echo "Jenkins container already running"
fi

# Creeer directory 
mkdir poc
cd poc

# Curl opensource project
curl https://start.spring.io/starter.zip \
  -d dependencies=web,actuator \
  -d javaVersion=21 \
  -d type=maven-project \
  -o demo.zip

# Unzip project
unzip demo.zip