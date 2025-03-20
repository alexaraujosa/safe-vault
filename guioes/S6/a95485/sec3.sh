#!/bin/sh

EXEC="bin/dog"

# Exercício 1
gcc -o $EXEC "$EXEC.c"

# Exercício 2
sudo useradd userssi

# Exercício 3
sudo chown userssi $EXEC
sudo chown userssi braga.txt

# Exercício 4
./$EXEC braga.txt

# Exercício 5
sudo chmod a+s $EXEC

# Exercício 6
./$EXEC braga.txt
# Os conteúdos do ficheiro braga.txt são apresentados no terminal.
# Isto acontece porque o binário tem o suid ativado, o que faz com que o
# este seja executado com as permissões do dono do ficheiro, neste caso,
# o utilizador userssi, que tem permissões de leitura sobre o ficheiro.
# Binários com suid ativado e cujo dono é root têm permissões de root,
# o que pode permitir elevação de privilégios.

# Note: SUID does not work on shell scripts on most modern Linux distributions.
