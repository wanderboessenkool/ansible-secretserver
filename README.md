Ansible Secret Server
=====================

A module for retrieving secrets from Thycotic Secret Server

Installation
------------

Place the file ```secretserver.py``` in one of the directories (or a
subdirectory) listed in the module path of ```ansible --version```.

Usage
-----

You can use ```ansible-doc secretserver``` after installation to view the docs. A short example is listed here as well

Example
-------
```yaml
- name: Retrieve the secret 513
  secretserver:
    uri:  https://secret.exampl.com/SecretServer/webservices/sswebservice.asmx/
    username: SoloH
    password: IheartWookies
    domain: mfalcon
    secretid: 513
  register: mysecret

- name: Show username and password
  debug:
    msg: "Your username is {{ mysecret.secret.Items.Username.Value }} and your password is {{ mysecret.secret.Items.Password.Value }}"
```
