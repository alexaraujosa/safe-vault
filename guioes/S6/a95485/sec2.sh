#!/bin/sh

# Exercício 0
cat /etc/passwd
cat /etc/group

# Exercício 1
sudo useradd miguel
sudo useradd alex
sudo useradd rafael

# Exercício 2
sudo groupadd grupo-ssi
sudo usermod -a -G grupo-ssi miguel
sudo usermod -a -G grupo-ssi alex
sudo usermod -a -G grupo-ssi rafael

sudo groupadd par-ssi
sudo usermod -a -G par-ssi alex
sudo usermod -a -G par-ssi rafael

# Exercício 3
cat /etc/passwd
cat /etc/group
# Sim, foram adicionadas as entradas dos novos utilizadores e grupos.

# Exercício 4
sudo chown miguel braga.txt

# Exercício 5
sudo su miguel -c "cat braga.txt"

# Exercício 6
sudo su miguel

# Exercício 7
id
groups
# Tanto uid como o gid foram atualizados para o do user miguel.
# Para além disso o user miguel pertence ao grupo grupo-ssi.

# Exercício 8
sudo su -c alex "cat braga.txt"
# O utilizador alex não tem permissões de leitura sobre o ficheiro braga.txt.

# Exercício 9
cd dir2 || echo "Couldn't change directory to dir2"
# bash: pushd dir2 || echo "Couldn't change directory to dir2"
# A diretoria dir2 não tem permissões de execução sendo impossível mudar para ela.
