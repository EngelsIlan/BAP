# Bachelors Thesis: CRA-Compliance in CI/CD Pipelines

## Working tree

```tree
- BAP/
  - .git/
  - .gitignore
  - Jenkinsfile
  - README.md
  - Vagrant/
    - .vagrant/
    - scripts/
      - cicd.sh
    - vagrant-hosts.yml
    - Vagrantfile
```

Credits voor Vagrantfile & vagrant-hosts.yml aan Dhr. B. Van Vreckem

## Documentation

### SonarQube

SonarQube doet SAST

Niet vergeten:
SonarQube -> Administration -> Configuration -> Webhooks -> Create

```conf
Name: Jenkins
URL: http://172.17.0.1:8080/sonarqube-webhook/
```

Anders blijft SonarQube runnen zonder einde (geen return URL om resultaat naartoe te sturen)
