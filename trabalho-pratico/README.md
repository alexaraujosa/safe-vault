# Relatório - Serviço de Cofre Seguro

## Introdução

TODO

## Arquitetura do Serviço

- Imagem descritiva
- Argumentos passados para cada programa
- Módulos do serviço
- Referir o estilo de servidor (semelhante a zero-trust)
TODO

## Comunicação entre cliente e servidor

- Utilização do módulo SSL
- Wrapper em volta do socket
- Context do módulo SSL (sem falar muito nos certificados)
- Encriptação envolvida (referindo a garantia de autenticidade, integridade e confidencialidade)
- Formato dos pacotes (header + payload)
- Comunicação sequencial (1 thread por cliente)
TODO

## Autenticação de clientes e servidor

- Context do módulo SSL (referindo pormenorizadamente sobre os certificados)
- Validação de certificados (campos)
- Validação de certificados dos dois lados do canal de comunicação (referindo o propósito e os ataques que bloqueia)
- Bloqueio de ataques reply/mitm
- Geração de certificados no lado do servidor
TODO

## Gestão de utilizadores, grupos e ficheiros

- Criação da nossa própria gestão (referindo o porquê de não utilizarmos primitivas do linux e a possibilidade de execução em diversos sistemas operativos)
- Encriptação envolvida (conteúdo de ficheiros, salvaguarda de chaves públicas, simétricas)
- Suposta re-encriptação de conteúdos ao revogar permissões
- Formato dos identificadores unicos
TODO

## Execução de comandos

A aplicação do cliente implementa uma diversidade de comandos que permitem aos utilizadores interagirem
com o serviço de cofre seguro. Estes comandos em conjunto com o sistema de gestão criado levam à 
cobertura de todas as funcionalidades descritas no enunciado, nomeadamente, a manipulação de ficheiros e 
a gestão de grupos. Para além desta base, a equipa de trabalho acrescentou comandos que permitem uma maior
composição a nível dos grupos através da criação de uma nova entidade, os moderadores, que possuem, para
além da permissão de escrita em ficheiros do grupo, a possibilidade de adicionarem e removerem novos membros
aos grupos, refletindo um maior poder administrativo nesta componente do serviço, mesmo quando o dono do grupo 
não está disponível. Por outro lado, o desenvolvimento de um sistema de _log_ persistente, tal como será
detalhado posteriormente, levou à necessidade de serem criados mais comandos, possibilitando a consulta
dessas mesmas _logs_, de forma global ou seletiva por parte dos clientes.

TODO agrupar os comandos por categoria e listá-los
TODO falar sobre os comandos adicionais implementados, bem como a nova opcao do list e o delete group file,
que o dono do grupo apaga o ficheiro apenas no grupo, nao tendo poder para apagar o ficheiro no vault do user,
e o dono do ficheiro pode apagar o ficheiro apenas no grupo, ou entao depois apagar do seu vault tambem.

- Referir os comandos implementados
- Validação em ambos os lados (evitar sobrecarga no server + pacotes com valores alterados a meio do envio, exemplificando)
- Referir que a validação é suportada pela nossa criação da gestão de utilizadores/grupos/ficheiros (moderadores)
- Referir ataques bloqueados com validações de parâmetros (ex.: privilege escalation nos grupos)
- Referir prevenção de file enumeration (ex.: tentar ler o conteúdo de um vault diz que ou é erro de permissão ou não existe, em vez de dizer se existe ou não)
- Imagens com pacotes capturados pelo sniffer, mostrando o conteudo encriptado e desencriptado
TODO

## Sistema de log

- Referir o tipo de logs implementado
- Formato do ficheiro que contem a informação (similar à config na primeira layer "user"/"groups")
TODO

## Trabalho futuro

TODO
- Encriptação com Curvas Elípticas por uma maior força criptográfica em relação ao tamanho da chave.
- Próprio formato do sistema de logs, em vez de guardar em ficheiros json
- File enumeration

No âmbito adicional aos conteúdos programáticos da Unidade Curricular de Segurança
de Sistemas de Informação, a equipa de trabalho poderá desenvolver um servidor com
concorrência, permitindo que vários clientes interajam com o serviço de cofre seguro
em simultâneo. Para tal implementação, a equipa de trabalho poderá utilizar uma *thread*
por pedido, ou então um *thread pool*, permitindo que o servidor tenha um número
fixo de *threads* disponíveis para atender os pedidos dos clientes. Esta implementação
precisaria de considerar a sincronização de dados entre as várias *threads*, sendo
assim necessário o uso de um *lock* global para os metadados do servidor, podendo
ser um *read-write lock* dependendo da frequência de leitura e escrita nos metadados
consoante os pedidos dos clientes. Para além disso, é necessário a implementação
de um *lock* por cada ficheiro no cofre seguro, de forma a evitar situações adversas
como, por exemplo, um cliente ler um ficheiro enquanto outro cliente o está a escrever.
Deste modo, seria implementada uma estrutura de dados para os *locks* de cada ficheiro,
podendo esta ser preguiçosa, ou seja, só criar o *lock* quando o ficheiro é acedido pela
primeira vez. Para além disso, a equipa de trabalho poderá implementar um sistema
de *caching* para os conteúdos encriptados dos ficheiros, de forma a evitar o acesso
repetido ao disco, melhorando assim o desempenho do servidor.

## Possíveis valorizações

- Lista com todas as valorizações que foram implementadas e detalhadas no relatório
- Atomic writes
- Path traversal
- Validação de parâmetros tanto no cliente (para evitar sobrecarga no *server*) como no *server*
- OOM protection (*validate max size*) (zero-trust)

## Conclusão

TODO
