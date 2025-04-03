#!/bin/bash

sudo useradd -M a104257
sudo useradd -M a95485

sudo groupadd grupo-ssi
sudo groupadd par-ssi

sudo usermod -aG grupo-ssi a104257
sudo usermod -aG grupo-ssi a95485
sudo usermod -aG grupo-ssi rafaelsf
sudo usermod -aG par-ssi a104257
sudo usermod -aG par-ssi a95485

# /etc/passwd changed:
# - New entries added:
# -- a104257:x:1001:1001::/home/a104257:/bin/sh
# -- a95485:x:1002:1002::/home/a95485:/bin/sh
#
# /etc/group changed:
# - New entries added:
# -- grupo-ssi:x:1003:a104257,a95485,rafaelsf
# -- par-ssi:x:1004:a104257,a95485

# 7.
# > id
# uid=1001(a104257) gid=1001(a104257) groups=1001(a104257),1003(grupo-ssi),1004(par-ssi)
# > groups
# a104257 grupo-ssi par-ssi

# 8. Não há diferença de comportamento aparente.

# 9. Não é permitido o acesso ao diretório "dir2" para o utilizador a104257, dado que apenas o dono do ficheiro,
#  "rafaelsf" tem permissões de leitura.
