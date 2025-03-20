#!/bin/sh

# Install ACL utilities with:
# sudo apt-get install acl &>/dev/null

# Exercicio 1
getfacl porto.txt
# # file: porto.txt
# # owner: ubuntu
# # group: ubuntu
# user::rw-
# group::r--
# other::r--

# Exercicio 2
setfacl -m g:grupo-ssi:w porto.txt

# Exercicio 3
getfacl porto.txt
# # file: porto.txt
# # owner: ubuntu
# # group: ubuntu
# user::rw-
# group::r--
# other::r--
# group:grupo-ssi:rw-
# mask::rw-

# É possível ver que o grupo grupo-ssi tem permissões de escrita sobre o ficheiro porto.txt,
# com adição de permissões de escrita para o grupo grupo-ssi e a máscara de permissões.
# A máscara de permissões (mask::rw-) define o nível máximo de permissões aplicáveis.
# Mesmo que um grupo ou usuário tenha permissões mais amplas, a máscara pode limitá-las.

# Exercicio 4
sudo runuser -u miguel -- sh -c 'echo "Test" >> porto.txt'  # Execute as miguel in a clean environment
cat porto.txt

# Não é possível adicionar conteúdo ao ficheiro porto.txt,
# visto que o utilizador miguel não pertence ao grupo grupo-ssi e
# não tem permissões de escrita sobre o ficheiro.
