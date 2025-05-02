# Relatório - Serviço de Cofre Seguro

## Introdução

TODO

## Arquitetura do Serviço

- Imagem descritiva
- Argumentos passados para cada programa
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
TODO

## Execução de comandos

- Referir os comandos implementados
- Validação em ambos os lados (evitar sobrecarga no server + pacotes com valores alterados a meio do envio, exemplificando)
- Referir comandos suportados pela nossa criação da gestão de utilizadores/grupos/ficheiros (moderadores)
- Referir ataques bloqueados com validações de parâmetros (ex.: privilege escalation nos grupos)
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