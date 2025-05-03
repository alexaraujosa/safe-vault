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

- Próprio formato do sistema de logs, em vez de guardar em ficheiros json
- Maior concorrência no servidor, permitindo um cliente enviar vários pedidos ao mesmo tempo

TODO

## Possíveis valorizações

- Lista com todas as valorizações que foram implementadas e detalhadas no relatório
TODO

## Conclusão

TODO