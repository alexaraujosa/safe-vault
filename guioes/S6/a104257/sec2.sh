#!/bin//bash

# Exercicio 0
cat /etc/passwd
cat /etc/group

# Exercicio 1
sudo useradd alex
sudo useradd miguel
sudo useradd rafael

# Exercicio 2
sudo groupadd grupo-ssi
sudo usermod -a -G grupo-ssi alex
sudo usermod -a -G grupo-ssi miguel
sudo usermod -a -G grupo-ssi rafael
sudo groupadd par-ssi
sudo usermod -a -G par-ssi miguel
sudo usermod -a -G par-ssi rafael

# Exercicio 3
cat /etc/passwd
cat /etc/group
# Sim, foram adicionadas as entradas dos novos utilizadores e dos novos grupos.

# Exercicio 4
sudo chown alex braga.txt

# Exercicio 5
cat braga.txt

# Exercicio 6
sudo su alex

# Exercicio 7
id
groups
# Agora visualizo que o uid e gid passaram a ter outro valor, nomeadamente o nome do user que dei login. Para alem disso, nos groups visualizo o grupo privado do user e o grupo-ssi

# Exercicio 8
cat braga.txt
# Agora ja consigo visualizar o conteudo do ficheiro, uma vez que sou o owner do mesmo.

# Exercicio 9
cd dir2
# De notar que o cd nao funciona dentro do script.
# Nao consigo  mudar para essa diretoria, ja que nao tenho permissoes
