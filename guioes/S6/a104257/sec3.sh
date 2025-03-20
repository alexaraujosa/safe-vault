#!/bin/bash

# Exercicio 2
sudo useradd userssi

# Exercicio 3
sudo chown userssi catter
sudo chown userssi braga.txt

# Exercicio 4
./catter braga.txt

# Exercicio 5
sudo chmod u+s catter

# Exercicio 6
./catter braga.txt
# Agora conseguimos visualizar o conteudo do ficheiro, uma vez que, apesar de o utilizador ubuntu nao ter permisoes de o visualizar, como o ficheiro possui o suid, este executar como sudo,
# tendo, assim, permissoes para visualizar o conteudo.
