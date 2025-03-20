#!/bin/bash

# Exercicio 1
getfacl porto.txt

# Exercicio 2
setfacl -m g:grupo-ssi:w porto.txt

# Exercicio 3
getfacl porto.txt
# Agora visualizo a entrada relativa ao grupo-ssi que tem a permissao de escrita, para alem de outra novo entrada (mask) tambem possuir as mesmas permissoes

# Exercicio 4
sudo su alex
echo "aoksdoaskd" >> porto.txt
cat porto.txt
# Nao consigo visualizar o conteudo, uma vez que o grupo do utilizador (grupo-ssi) nao tem permissoes de leitura sobre o ficheiro, apesar de conseguir escrever nele.
