### template for after manual setup
import docker
import datetime
import secrets
import platform
import os
import psutil

# parm
user = 'xTestUser'

now = datetime.datetime.now().strftime(r'%Y.%m%d.%H%M.%S')
token = secrets.token_urlsafe(96) # 96 might be the max

def sql(client, user, now, token):
    # sql - user container
    name = 'sql-'+user
    #ext = 1433
    #local = secrets.choice(range(1, 65534))
    current = client.containers.list(all=True, filters={"name": name})
    if len(current) > 0:
        for i in current:
            i.remove(v=True, force=True)
    client.images.build(
        path="images",
        dockerfile="sql.dockerfile",
        tag="sql:latest",
        nocache=True,
        pull=True,
        rm=True,
        forcerm=True
        # squash=True
    )


def iis(client, user, now, token):
    name = 'iis-'+user
    #ext = 8000
    #local = 80
    current = client.containers.list(all=True, filters={"name": name})
    if len(current) > 0:
        for i in current:
            i.remove(v=True, force=True)
    client.images.build(
        path="images",
        dockerfile="iis.dockerfile",
        tag="iis:latest",
        nocache=True,
        pull=True,
        rm=True,
        forcerm=True
        # squash=True
    )



print('user:', user)
print('token:', token)
print('version:', now)
# ref: https://docker-py.readthedocs.io/en/stable/
client = docker.from_env()

# sql
#sql(client, user, now, token)

# iis
#iis(client, user, now, token)
