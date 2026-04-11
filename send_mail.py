import smtplib
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

username = sys.argv[1]
password = sys.argv[2]
job_name = sys.argv[3]
build_number = sys.argv[4]
build_url = sys.argv[5]

msg = MIMEMultipart("alternative")
msg["Subject"] = f"CRA Pipeline FAILED: {job_name} - Build #{build_number}"
msg["From"] = username
msg["To"] = username

body = f"""
CRA Compliance Pipeline - FAILURE RAPPORT

Job:        {job_name}
Build:      #{build_number}
Status:     FAILED
Build URL:  {build_url}

Een of meerdere security checks zijn gefaald:
- HIGH/CRITICAL CVE gevonden (CVSS >= 7.0)
- SonarQube Quality Gate gefaald
- BSI TR-03183-2 SBOM validatie gefaald

Bekijk het volledige rapport via:
{build_url}artifact/
"""

msg.attach(MIMEText(body, "plain"))

try:
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.ehlo()
    server.starttls()
    server.ehlo()
    server.login(username, password)
    server.sendmail(username, username, msg.as_string())
    print("Mail verstuurd!")
    server.quit()
except Exception as e:
    print(f"Mail fout: {e}")