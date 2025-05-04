# Relatório - Serviço de Cofre Seguro

## Índice

- [Introdução](#introdução)
- [Arquitetura do Serviço](#arquitetura-do-serviço)
- [Comunicação entre Cliente e Servidor](#comunicação-entre-cliente-e-servidor)
  - [*TLS Handshake*](#tls-handshake)
  - [Tratamento de Conexões](#tratamento-de-conexões)
  - [Autenticação](#autenticação)
  - [Estrutura do Pacote](#estrutura-do-pacote)
- [Autenticação de Clientes e Servidor](#autenticação-de-clientes-e-servidor)
  - [*Keystore*](#keystore)
  - [`Certutil`](#certutil)
- [Encriptação de Ficheiros](#encriptação-de-ficheiros)
  - [Gestão de Chaves](#gestão-de-chaves)
    - [Client-side](#client-side)
    - [Server-side](#server-side)
  - [Esquema de Encriptação de Ficheiros](#esquema-de-encriptação-de-ficheiros)
    - [Ficheiros Pessoais](#ficheiros-pessoais)
      - [Adicionar Ficheiro ao Cofre Pessoal](#adicionar-ficheiro-ao-cofre-pessoal)
    - [Partilha de Ficheiros](#partilha-de-ficheiros)
      - [Partilhar Ficheiro](#partilhar-ficheiro)
    - [Ficheiros de Grupos](#ficheiros-de-grupos)
      - [Criar Grupo](#criar-grupo)
      - [Adicionar Membro ao Grupo](#adicionar-membro-ao-grupo)
      - [Criar Ficheiro no Grupo](#criar-ficheiro-no-grupo)
    - [Modelo de Encriptação para Ficheiros de Grupos](#modelo-de-encriptação-para-ficheiros-de-grupos)
  - [Leitura de Ficheiros](#leitura-de-ficheiros)
  - [Requisitos de Segurança](#requisitos-de-segurança)
- [Gestão de Utilizadores, Grupos e Ficheiros: Metadata](#gestão-de-utilizadores-grupos-e-ficheiros-metadata)
    - [Objetivo](#objetivo)
    - [Vantagens](#vantagens)
    - [Estrutura](#estrutura)
    - [Notas](#notas)
- [Execução de Comandos](#execução-de-comandos)
- [Sistema de *Logging*](#sistema-de-logging)
- [Trabalho Futuro](#trabalho-futuro)
- [Possíveis Valorizações](#possíveis-valorizações)
- [Conclusão](#conclusão)

## Introdução

O presente relatório descreve o desenvolvimento de um serviço de Cofre Seguro,
concebido para permitir aos utilizadores de uma organização armazenar e partilhar
ficheiros de texto com garantias de **autenticidade**, **integridade** e **confidencialidade**.
O sistema foi implementado em Python, adotando uma arquitetura cliente-servidor,
na qual o servidor centraliza o estado da aplicação e os clientes interagem com
o serviço através de uma interface textual baseada em comandos.

A solução proposta garante a gestão segura de ficheiros pessoais e partilhados,
possibilitando igualmente a criação e administração de grupos, com controlo rigoroso
das permissões atribuídas aos diferentes utilizadores. A comunicação entre os clientes
e o servidor é assegurada pelo protocolo **TLSv1.3**, de modo a garantir a autenticidade,
confidencialidade e integridade dos dados em trânsito. Adicionalmente, os ficheiros
são protegidos através de um esquema de encriptação híbrido, que recorre a algoritmos
simétricos (AES-GCM) para o conteúdo e a algoritmos assimétricos (RSA) para a troca
segura de chaves.

Este documento encontra-se estruturado em capítulos que abordam a arquitetura da
aplicação, os mecanismos de segurança aplicados, a estrutura dos metadados, a
execução dos comandos suportados e sugestões para possíveis extensões futuras.
A implementação cumpre os requisitos especificados no enunciado, incluindo ainda
funcionalidades extra, como um sistema de registo de eventos (*logging*) e a introdução
de moderadores nos grupos, permitindo uma gestão mais flexível e controlada dos acessos.

O relatório visa, assim, apresentar uma visão técnica fundamentada sobre as decisões
tomadas, destacando os aspetos críticos à robustez, segurança e escalabilidade
do serviço.

## Arquitetura do Serviço

- Imagem descritiva
- Argumentos passados para cada programa
- Módulos do serviço
- Referir o estilo de servidor (semelhante a zero-trust)
TODO

## Comunicação entre Cliente e Servidor

A comunicação entre o cliente e o servidor foi implementada com recurso aos módulos
*built-in* do python `ssl` e  `socket`, em adição aos módulos `cryptography` e `pymongo`.

A comunicação é estabelecida através de sockets TCP, cujo controlo é passado a um
contexto SSL configurado para usar o protocolo `TLSv1.3` e negociar automaticamente
os pares AEAD `(AC,AH)` (onde `AC` é o Algoritmo de Cifragem e `AH` é o Algoritmo de *Hashing*)
a serem usados durante a sessão, entre os disponíveis no sistema pertencentes à lista
(`AES_128_GCM`, `SHA256`), (`AES_256_GCM`, `SHA384`), (`ChaCha20_Poly1305`, `SHA256`).
A troca de chaves no *handshake* inicial é efetuada utilizando o algoritmo de troca
de chaves *Elliptic-Curve Diffie-Hellman Ephemeral* utilizando uma das curvas `x25519`,
`secp256r1`, `x448`, negociadas ao mesmo tempo que os pares AEAD.

### *TLS Handshake*

O *handshake* ocorre como definido na norma `TLSv1.3`, salvo o uso das funções de
`Early Data` e `Encrypted Extensions`:
1. O cliente envia um pacote `ClientHello`, contendo a lista de pares AEAD que o
    mesmo suporta, as curvas que suporta para o algoritmo *ECDHE*;
2. O servidor envia um pacote `ServerHello`, contendo o par AEAD e a curva que
    selecionou para utilizar na comunicação,  juntamente do seu certificado, bem
    como o certificado `VAULT_CA`. Neste ponto, o servidor e o cliente derivam,
    através do algoritmo *ECDHE*, as chaves de encriptação unidirecionais para o
    resto do *handshake*, `SERVER_HANDSHAKE_TRAFFIC_SECRET` e `CLIENT_HANDSHAKE_TRAFFIC_SECRET`.
    Os certificados do pacote  `ServerHello` já se encontram encriptados pelo
    `SERVER_HANDSHAKE_TRAFFIC_SECRET`;
3. O cliente envia pacote com o seu próprio certificado, e também o certificado `VAULT_CA`;
4. O servidor envia um pacote `NewSessionTicker`, invalidando as chaves
    `SERVER_HANDSHAKE_TRAFFIC_SECRET` e `CLIENT_HANDSHAKE_TRAFFIC_SECRET`.
    Neste ponto, o servidor e o cliente derivam novas chaves de encriptação unidirecionais,
    válidas para o resto da comunicação, `SERVER_TRAFFIC_SECRET_0` e `CLIENT_TRAFFIC_SECRET_0`.

### Tratamento de Conexões

Ao receber uma nova conexão, o servidor cria uma nova thread para receber e tratar
todos os pacotes provenientes da mesma conexão, sem impedir o servidor de receber
novas conexões, ou de responder a conexões existentes. Ao terminar a conexão com
um cliente, a thread associada à mesma é terminada.

Todos os pacotes após o *handshake* são encriptados utilizando a cifra selecionada
durante o mesmo, com as chaves de cifragem unidirecionais derivadas, `SERVER_TRAFFIC_SECRET_0`
e `CLIENT_TRAFFIC_SECRET_0` e autenticadas utilizando o algoritmo de *hashing* também
selecionado durante o *handshake*, garantindo a autenticidade, integridade e
confidencialidade de todas as mensagens durante o resto da comunicação.
Numa futura conexão, todas as chaves são regeneradas, de modo a impedir um *Replay Attack*
caso um atacante grave o tráfego durante uma sessão.

### Autenticação

A autenticação é efetuada através dos certificados, descritos em mais detalhe na
secção **Autenticação de clientes e servidor**. Tanto o servidor como o cliente
exigem e validam os certificados durante o handshake inicial e abortam a comunicação
caso os certificados não sejam válidos ou não correspondam aos certificados esperados
(no caso do cliente, se o certificado recebido pelo "servidor" não for o certificado
real do servidor, o cliente aborta a conexão unilateralmente. No caso do servidor,
se o certificado recebido for o certificado do servidor, ele aborta a conexão de
forma graciosa, enviando um pacote do tipo `AUTH_FAIL` antes de fechar o socket).

Um certificado é considerado inválido se:
1. Não seguir a estrutura como definida pela norma X.509;
2. Não tenha sido assinado pela Entidade de Certificação `VAULT_CA`M
3. A sua data de início de validade ainda não tenha sido ultrapassada;
4. A sua data de término de validade já tenha sido ultrapassada;
5. Não possuir o campo `SUBJECT.PSEUDONYM`;
6. O campo `SUBJECT.PSEUDONYM` não for igual a `VAULT_SERVER`, caso seja recebido pelo cliente;
7. O campo `SUBJECT.PSEUDONYM` for igual a um utilizador existente na base de dados,
    mas que tenha sido registado com uma chave pública diferente, caso seja recebido pelo servidor.

O ponto **6** impede que um atacante se consiga fazer passar pelo servidor perante um cliente ao utilizar um certificado
de cliente, válido em todos os pontos exceto o ponto em questão. No entanto, este ataque tem um impacto mínimo na
confidencialidade dos dados do cliente perante o servidor real, dado que o atacante não conseguiria ler os dados
enviados pelo servidor ao cliente, mesmo que servisse de *proxy*, dado não possuir a chave privada do cliente.

O ponto **7** impede que um atacante se consiga fazer passar por um outro cliente ao obter um certificado com o mesmo id
de utilizador de um outro cliente de modo ilícito, porém com uma chave pública diferente da original. Este ataque,
apesar de não conseguir comprometer a confidencialidade dos dados pertencentes ao cliente alvo já existentes no seu
vault por si só, dado não possuir a chave privada do cliente, podia ainda assim comprometer a integridade dos dados,
dado conseguir eliminar ficheiros do vault. Porém, não é possível partilhar o ficheiro com outros utilizadores,
comprometendo a confidencialidade, dado que o criptograma contendo a chave de cifragem do ficheiro foi encriptado com a
chave privada do cliente alvo, à qual o atacante não tem acesso. Pode, no entanto, "partilhar" o ficheiro na mesma,
resultando num criptograma inválido.

Dado que os certificados em si são utilizados como meio de autenticação e autorização, torna-se impossível executar um
ataque *Man-In-The-Middle*, já que o atacante só terá acesso aos seus próprios ficheiros caso use um outro certificado,
e é-lhe impossível ler as mensagens transmitidas caso use o certificado do cliente, dado não possuir a chave privada do
cliente.

### Estrutura do Pacote

Os pacotes transmitidos entre o servidor e o cliente são dicionários nativos do python serializados através do formato
BSON, disponibilizado pelo módulo `pymongo`. Todos os pacotes seguem a mesma estrutura geral:

| Chave     | Tipo         | Descrição                                                                   |
|:----------|:-------------|:----------------------------------------------------------------------------|
| `version` | `uint32`     | A versão da estrutura dos pacotes utilizada. Versão atual: `1`              |
| `type`    | `PacketType` | O tipo de pacote recebido. Afeta o processador a utilizar para o `payload`. |
| `payload` | `Document`   | O corpo do pacote em si. A sua estrutura depende do tipo de pacote.         |

Uma classe de pacotes, ditos de controlo, possui uma estrutura fixa e é potencialmente utilizada por qualquer operação:
- `SUCCESS`, `ERROR`: Enviados pelo servidor como resposta a uma operação, comunicando que a operação foi realizada com
sucesso, ou um erro ocorreu durante a sua execução, respetivamente.
- `NEEDS_CONFIRMATION`: Enviado pelo servidor sempre que é exigida uma confirmação ao cliente numa operação destrutiva
(como o comando `delete-user`). O cliente deverá enviar um pacote `CONFIRM` ou `ABORT` de forma a sinalizar ao servidor
a decisão do utilizador. O cliente não deverá enviar qualquer outro tipo de pacote antes dessa resposta.
- `CONFIRM`, `ABORT`: Enviados pelo cliente para sinalizar a resposta a um pacote `NEEDS_CONFIRMATION`, positiva ou
negativa, respetivamente.
- `AUTH_WELCOME`, `AUTH_WELCOME_BACK`: Enviados pelo servidor imediatamente após uma autenticação bem sucedida. O
primeiro só será enviado na primeira vez que o utilizador se conecta ao servidor, passando a ser enviado o último nas
vezes seguintes.
- `AUTH_USER_ALREADY_TOOK`: Enviado pelo servidor caso receba um certificado válido com o mesmo id de utilizador de um
outro existente na sua base de dados, mas com uma chave pública diferente. A sua recepção deverá abortar imediatamente
a execução do cliente.
- `AUTH_FAIL`: Enviado pelo servidor caso ocorra um erro ao autenticar o utilizador. A sua recepção deverá abortar
imediatamente a execução do cliente.

Os restantes pacotes (`ADD`, `LIST`, `SHARE`, `DELETE`, `REPLACE`, `DETAILS`, `REVOKE`, `READ`, `GROUP_CREATE`,
`GROUP_DELETE`, `GROUP_ADD_USER_INIT`, `GROUP_ADD_USER`, `GROUP_DELETE_USER`, `GROUP_LIST`, `GROUP_ADD_INIT`,
`GROUP_ADD`, `GROUP_DELETE_FILE`, `GROUP_CHANGE_PERMISSIONS`, `GROUP_ADD_MODERATOR`, `GROUP_REMOVE_MODERATOR`,
`LOGS_GLOBAL`, `LOGS_GROUP_OWNER`, `LOGS_FILE`, `LOGS_GROUP`) possuem `payloads` dinâmicos controlados pelos operadores
tanto do cliente como do servidor.

## Autenticação de Clientes e Servidor

A autenticação durante a comunicação é baseada em torno de certificados extraídos a partir de *keystores* no formato
`PKCS12`. Tanto o servidor como cada cliente possuem os seus próprios *keystores* privados, que contêm a sua
identificação.

### *Keystore*

As *keystores* são ficheiros no formato `PKCS12` que contém uma chave privada assimétrica, um certificado associado à
chave publica, par da chave privada anterior, e o certificado da Entidade de Certificação `VAULT_CA`. As *keystores* são
geradas com recurso ao módulo `certutil`, localizado em `common/certutil.py`. Cada *keystore* contém os dados necessários
para identificar unicamente uma entidade, pelo que deve em teoria ser mantido privado a qualquer momento. Por limitações
inerentes ao módulo `ssl`, os conteúdos da *keystore*, nomeadamente o certificado e a chave privada têm que ser gravados
no disco e passados como `filepath` ao contexto SSL, pelo que se faz uso do módulo *built-in* do python `tempfile` para
criar estes ficheiros temporários.. Esta é uma limitação que não possuí nenhuma alternativa conhecida
(ver: [https://github.com/python/cpython/issues/60691](https://github.com/python/cpython/issues/60691)).

### `Certutil`

O módulo `certutil.py` foi criado para facilitar a criação de certificados de entidades
de certificação auto-assinados e *keystores*.
- O comando `genca` permite gerar um certificado para uma Entidade de Certificação (por defeito `VAULT_CA`),
conjuntamente com a sua chave privada, necessária para a criação dos certificados utilizados nas *keystores*.
- O comando `genstore` permite gerar uma *keystore* associada a um dado id e nome de utilizador, com uma data de
expiração.

Todos os certificados possuem os seguintes campos em comum:

| Chave                      | Valor                   |
|:---------------------------|-------------------------|
| `COUNTRY_NAME`             | `PT`                    |
| `STATE_OR_PROVINCE_NAME`   | `Minho`                 |
| `LOCALITY_NAME`            | `Braga`                 |
| `ORGANIZATION_NAME`        | `Universidade do Minho` |
| `ORGANIZATIONAL_UNIT_NAME` | `SSI VAULT SERVICE`     |

O Certificado da Entidade de Certificação possuí adicionalmente os seguintes campos:

| Chave         | Valor                   |
|:--------------|-------------------------|
| `COMMON_NAME` | `SSI VAULT SERVICE CA`  |
| `PSEUDONYM`   | `VAULT_CA`              |

> Adicionalmente, o Certificado da Entidade de Certificação tem uma data de expiração
fixa de 365 dias a partir da data de geração.

Os Certificado das *keystores* possuem adicionalmente os seguintes campos:

| Chave         | Valor                |
|:--------------|----------------------|
| `COMMON_NAME` | O nome do utilizador |
| `PSEUDONYM`   | O id do utilizador   |

Todas as chaves são geradas utilizando o algoritmo `RSA2048`, com um exponente público fixo `65537`. Foi ponderado o uso
de chaves de criptografia assimétrica de Curvas Elípticas, porém, dado as chaves serem também utilizadas para a
encriptação de dados, foi decidido ultimamente utilizar o algoritmo `RSA`, apesar das chaves CE serem menores em
tamanho. No entanto, uma possível melhoria seria migrar a cifragem de dados para utilizar um algoritmo de cifragem sobre
Curvas Elípticas, como o algoritmo `ElGamal`.

## Encriptação de Ficheiros

Para encriptação de ficheiros a equipa trabalho decidiu utilizar um esquema de
encriptação híbrido, onde a encriptação simétrica é utilizada para encriptar o
ficheiro e a encriptação assimétrica é utilizada para encriptar a chave simétrica.

Este esquema de encriptação híbrido permite uma maior eficiência na encriptação
e desencriptação de ficheiros, uma vez que a encriptação simétrica é mais rápida
que a encriptação assimétrica.

Este modelo também facilita a partilha segura de ficheiros com múltiplos destinatários,
pois a mesma chave simétrica pode ser encriptada várias vezes com diferentes chaves
públicas, sem necessidade de re-encriptar o conteúdo do ficheiro.

Além disso, este método melhora a escalabilidade e flexibilidade dos sistemas de
segurança ao separar claramente os processos de encriptação de dados e gestão de
chaves.

### Gestão de Chaves

#### *Client-side*

Cada cliente irá utilizar a sua chave privada (do seu *keystore* PKCS12) para:
- Assinaturas digitais (autenticidade);
- Desencriptação das chaves simétricas dos ficheiros a que tem acesso.

#### *Server-side*

O servidor irá manter:
- Credenciais do servidor (PKCS12 *keystore*);
- Uma chave pública para cada cliente para verificar assinaturas;
- As chaves simétricas encriptadas com a chave pública dos respetivos clientes.

### Esquema de Encriptação de Ficheiros

#### Ficheiros Pessoais

##### Adicionar Ficheiro ao Cofre Pessoal

1. O cliente gera uma chave simétrica aleatória (AES) para o ficheiro;
2. O cliente encripta o ficheiro com a chave simétrica gerada no passo 1;
3. O cliente encripta a chave simétrica com a sua chave pública;
4. O cliente envia, num canal seguro, o seguinte para o servidor:
    - Ficheiro encriptado
    - Chave simétrica encriptada
    - Metadados
        - Nome do ficheiro
        - Tamanho do ficheiro em bytes
5. O servidor armazena o ficheiro encriptado na diretoria `vault` e os restantes
dados no ficheiro JSON de metadados, assim como devolve o ID do ficheiro ao cliente.

#### Partilha de Ficheiros

##### Partilhar Ficheiro

1. O cliente recupera a chave simétrica do ficheiro do servidor,
    esta previamente gerada no passo 1 do adicionar ficheiro ao cofre pessoal;
2. O cliente desencripta a chave simétrica com a sua chave privada;
3. O cliente encripta a chave simétrica com a chave pública do destinatário;
4. O cliente envia, num canal seguro, o seguinte para o servidor:
    - ID do ficheiro
    - Chave simétrica encriptada com a chave pública do destinatário
5. O servidor armazena a chave simétrica encriptada no ficheiro JSON de metadados
    do destinatário.

#### Ficheiros de Grupos

##### Criar Grupo

1. O cliente gera uma chave simétrica aleatória (AES) para o grupo,
    esta chave é utilizada para encriptar os ficheiros do grupo;
2. O cliente encripta a chave simétrica com a sua chave pública;
3. O cliente envia, num canal seguro, o seguinte para o servidor:
    - ID/Nome do grupo
    - Chave simétrica encriptada com a chave pública do cliente

##### Adicionar Membro ao Grupo

1. O cliente requisita a chave simétrica do grupo e a chave pública do novo membro;
2. O cliente desencripta a chave simétrica com a sua chave privada;
3. O cliente encripta a chave simétrica com a chave pública do novo membro;
4. O cliente envia, num canal seguro, o seguinte para o servidor:
    - ID do grupo
    - ID do novo membro
    - Chave simétrica encriptada com a chave pública do novo membro

##### Criar Ficheiro no Grupo

1. O cliente requisita a chave (mestra) simétrica do grupo do servidor;
3. O cliente desencripta a chave simétrica com a sua chave privada;
4. O cliente encripta os conteúdos do ficheiro com a chave simétrica do grupo;
5. O cliente envia, num canal seguro, o seguinte para o servidor:
    - Ficheiro encriptado
    - ID do grupo
    - Metadados
        - Nome do ficheiro
        - Tamanho do ficheiro em bytes

#### Modelo de Encriptação para Ficheiros de Grupos

A equipa decidiu utilizar uma chave mestra simétrica para encriptar os ficheiros
de grupos, em vez de, por exemplo, gerar uma chave simétrica para cada ficheiro,
por vários motivos, dos quais se destacam:

##### Escalabilidade

Analisando um caso em que num grupo, com $N$ ficheiros e $M$ membros, é necessário
a re-encriptação de todos os ficheiros do grupo:

- **Caso com Chave Mestra**

O cliente, após a desencriptação de cada ficheiro com a chave mestra anterior,
gera uma nova chave simétrica para o grupo, e de seguida encripta a chave simétrica
com a chave pública de cada membro do grupo.

Tempo linear: $N + M$

- **Uma chave simétrica para cada ficheiro**

O cliente, após a desencriptação de cada ficheiro com a respetiva chave simétrica,
gera uma nova chave simétrica para cada ficheiro e para cada uma dessas chaves,
encripta com a chave pública de cada membro do grupo.

Tempo exponencial: $N \times M$

##### Eficiência

A adição de um novo membro ao grupo não requer a re-encriptação de todas
chaves simétricas dos ficheiros para que tal tenha acesso. Apenas a chave
simétrica do grupo é encriptada com a chave pública do novo membro.

##### Simplicidade de Gestão

A gestão de chaves simétricas é mais simples com uma chave mestra, pois o servidor
apenas precisa de armazenar uma chave simétrica encriptada por cada membro do grupo.

#### Leitura de Ficheiros

Para ler um ficheiro, o cliente tem de:

1. Requisitar os conteúdos do ficheiro e a respetiva chave simétrica encriptada;
2. Desencriptar a chave simétrica com a sua chave privada;
3. Desencriptar o ficheiro com a chave simétrica.

### Requisitos de Segurança

A integridade, autenticidade e confidencialidade dos conteúdos dos ficheiros bem como
das chaves simétricas guardadas nos metadados do servidor são garantidas através
do uso da encriptação simétrica AES-GCM, e da encriptação assimétrica RSA, respetivamente.

O AES é amplamente utilizado como um
algoritmo de encriptação simétrica que fornece proteção contra vários tipos de
ataques, incluindo ataques de força bruta e ataques de texto conhecido.

O GCM (Galois/Counter Mode) é um modo de operação que combina a encriptação
com a autenticação, garantindo que os dados não foram alterados durante a
transmissão, este modo utiliza um Message Authentication Code (MAC) para verificar
a integridade dos dados.

A equipa de trabalho decidiu utilizar o AES-GCM com 256 bits, para um alto nível
de segurança dos conteúdos dos ficheiros dos clientes.

A equipa de trabalho decidiu utilizar chaves RSA com 2048 bits, sendo que,
atualmente, é considerada segura para a encriptação de dados e permite a
encriptação e desencriptação mais rápida que chaves RSA com, por exemplo,
4096 bits.

---

**TODO** adicionar nota sobre a re-encriptação de chaves e conteúdos em revogações,
explicar o processo em diferentes casos, e o porquê de não o termos feito
(ACL garante + eficiência de revogação). num ambiente de produção deve-se ponderar
esta re-encriptação.

## Gestão de Utilizadores, Grupos e Ficheiros: Metadata

### Objetivo

A metadata é uma componente essencial do sistema de cofre seguro, responsável por
armazenar todas as informações necessárias para o funcionamento do serviço, incluindo:

- Dados dos utilizadores e as suas chaves públicas RSA;
- Informações sobre ficheiros armazenados;
- Estrutura de grupos e respetivas permissões;
- Relações de partilha e controlo de acesso.

Em conjunto com o módulo `server.operations`, esta garante o controlo de
acesso e gestão segura dos recursos do sistema. É persistida em formato JSON
no fim da execução do servidor e carregado automaticamente aquando da sua
inicialização.

### Vantagens

Optar por uma estrutura de metadata própria, em vez de depender unicamente das
permissões nativas dos sistemas POSIX, traz diversas vantagens, entre as quais
se destacam:

- **Funcionalidades avançadas**: Permite a implementação de mecanismos como
    partilhas granulares (com permissões distintas por utilizador ou grupo),
    controlo hierárquico de grupos e permissões temporárias ou condicionais,
    que não são suportados diretamente pelo modelo POSIX.
- **Maior controlo lógico e de segurança**: Garante uma gestão mais flexível e
    rigorosa do acesso, sem as limitações impostas pelo modelo tradicional de
    *ownership* e permissões do sistema de ficheiros.
- **Melhor desempenho**: Ao evitar chamadas ao sistema como `stat` ou `getfacl`
    em cada operação, reduz-se significativamente o número de *syscalls*, o que
    contribui para uma execução mais eficiente, sobretudo em cenários com grande
    volume de acessos ou utilizadores.

### Estrutura

```json
{
  "users": {
    "<user_id>": {                     // ID do utilizador, também desginado por username
      "created": "datetime",           // Data e hora da criação
      "groups": ["group1", "group2"],  // Grupos que o utilizador pertence
      "own_groups": ["group1"],        // Grupos criados pelo utilizador
      "moderator_groups": ["group2"],  // Grupos onde o utilizador tem privilégios de moderador
      "public_key": "public_key",      // Chave pública RSA do utilizador codificada em base64
      "files": {                       // Ficheiros de propriedade do utilizador
        "<file_id>": {
          "owner": "<user_id>",        // Dono do ficheiro (igual ao <user_id> pai)
          "size": "1024",              // Tamanho original do ficheiro em bytes
          "created": "datetime",       // Data e hora de criação
          "last_modified": "datetime", // Data e hora da última modificação
          "last_accessed": "datetime", // Data e hora do último acesso
          "key": "encrypted_key",      // Chave simétrica AES encriptada com a chave pública RSA
                                         // do dono codificada em base64
          "acl": {
            "users": {                 // Partilhas diretas com outros utilizadores
              "user2": "r",            // Permissões da partilha:
                                         // 'r' (leitura)
                                         // 'w' (leitura e escrita)
              "user3": "w"
            },
            "groups": ["group1"]       // Grupos a qual o ficheiro pertence
          }
        }
      },
      "shared_files": {                // Ficheiros partilhados com este utilizador
        "<user_id>": {                 // ID do utilizador que efetuou a partilha
          "<file_id>": {               // ID do ficheiro a ser partilhado
            "permissions": "r",        // Permissões
            "key": "encrypted_key"     // Chave simétrica AES encriptada com a chave pública RSA
                                         // do recepiente da partilha codificada em base64
          }
        }
      }
    }
  },
  "groups": {
    "<group_id>": {
      "owner": "<user_id>",            // Dono do grupo
      "created": "datetime",           // Data e hora da criação do grupo
      "moderators": [],                // Lista de moderadores do grupo
      "members": {                     // Membros do grupo
        "<user_id>": {                 // ID do membro
          "permissions": "w",          // Permissões do membro no grupo
          "key": "encrypted_key"       // Chave (mestra) simétrica do grupo encriptada com a
                                         // chave pública RSA do membro codificada em base64
        }
      },
      "files": {
        "<user_id>": ["file.txt"]      // Lista de ficheiros no grupo do dado membro
      }
    }
  }
}
```

### Notas

1. **Identificadores Únicos**:
    - `user_id`: Nome de utilizador, único e imutável, obtido através do campo
        `PSEUDONYM` do certificado X.509 (entre 1 a 256 caracteres alfanuméricos);
    - `file_id`: Segue o formato `user_id:filename`, onde `user_id` é o ID do dono
        do ficheiro e `filename` o nome (*basename*) do ficheiro
        (nome do ficheiro entre 1 a 256 caracteres);
    - `group_id`: Nome do grupo, único e imutável, definido pelo dono na sua criação.
        (entre 1 a 256 caracteres alfanuméricos).

2. **Segurança**:
    - Todas as chaves simétricas (AES) são armazenadas encriptadas com a chave
        pública (RSA) do respetivo utilizador, garantindo que o servidor não tem
        acesso às chaves nem ao conteúdo dos ficheiros;
    - A chave (mestra) simétrica de cada grupo é gerada pelo dono e encriptada
        com a chave pública de cada membro, garantindo que apenas estes
        conseguem aceder aos ficheiros do grupo;

3. **Controlo de Acesso**:
    - Modelo hierárquico de permissões:
        1. **Dono do ficheiro (*owner*)**
            - Permissões completas: ler (`r`), escrever (`w`), apagar e partilhar.
        2. **Acessos concedidos**
            - Partilhas diretas: com permissões atribuídas individualmente;
            - Membros de grupos: herdam as permissões definidas no grupo
                (note que o criador do grupo pode remover um ficheiro deste,
                contudo o dono original mantém o acesso).
        3. **Outros utilizadores**:
            - Sem quaisquer permissões.
    - O controlo de acesso é gerido por ACLs (Listas de Controlo de Acesso),
        onde cada ficheiro tem uma lista de recipientes de partilhas com permissões
        específicas, e, para grupos, as permissões são armazenadas na sua lista
        de membros.

4. **Eficiência**:
    - A estrutura é desenhada para minimizar o tempo de pesquisa, incluindo alguns
        dados redundantes para facilitar a verificação de permissões e pertença
        a grupos. O módulo `server.operations` assegura a consistência desses dados.

5. **Compatibilidade**:
    - **Multiplataforma**: Este formato JSON é compatível com qualquer sistema
        operativo, incluindo sistemas não POSIX como Windows. Esta abstração
        evita dependência de *syscalls* como `chmod`, `stat` ou `setfacl`, e do
        modelo de permissões baseado em UID/GID.
    - **Interoperabilidade**: A estrutura é autocontida e independente da plataforma,
        podendo ser facilmente exportada, transportada ou integrada com outros serviços.

No próximo capítulo aprofundar-se-á como o ficheiro de metadata é utilizado
aquando da execução de diferentes comandos do cliente, bem como abordar-se-á
o conceito introduzido de moderador de um grupo e comandos adicionais para além
dos requisitos inicialmente providenciados.

## Execução de Comandos

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

## Sistema de *Logging*

- Referir o tipo de logs implementado
- Formato do ficheiro que contem a informação (similar à config na primeira layer "user"/"groups")
TODO

## Trabalho Futuro

TODO
- Próprio formato do sistema de logs, em vez de guardar em ficheiros json

A equipa de trabalho teve em consideração o uso de encriptação com curvas elípticas,
uma vez que estas oferecem um nível de segurança superior a RSA para o mesmo tamanho
de chave. Contudo, após uma análise cuidadosa, a equipa decidiu não implementar,
na presente data, devido ao trabalho computacional acrescido dos clientes,
a relativa novidade deste método de encriptação na indústria e a segurança provada
do RSA para o tamanho de chave definido no projeto. Contudo, no futuro, caso fosse
uma melhoria viável do sistema, apenas seria necessário alterar a biblioteca de
encriptação usada pelo cliente, mais especificamente a classe responsável pela
encriptação assimétrica implementada e a atualização do modulo responsável pela
criação de certificados e *keystores*, com a nova geração de chaves.

No âmbito adicional aos conteúdos programáticos da unidade curricular de Segurança
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

## Possíveis Valorizações

A equipa de trabalho tomou as devidas precauções para garantir uma segurança acrescida
do sistema, das quais se destacam:

- **Validação de certificados**: O servidor valida os certificados dos clientes
    e vice-versa, garantindo que apenas clientes autorizados podem aceder ao serviço,
    bem como são verificadas as assinaturas digitais dos certificados, e respetivas
    datas de validade. No âmbito da testagem desta funcionalidade e exemplificação
    da usagem do módulo de [Utilidades de Certificados](common/certutil.py) desenvolvido,
    a equipa de trabalho produziu um *shell script*, em *bash*, que pode ser
    localizado em [scripts/gen_certs.sh](scripts/gen_certs.sh).
- **Validação de parâmetros**: Todos os parâmetros trocados entre o cliente e o servidor
    são validados, tanto no cliente com o intuito de evitar sobrecarga desnecessária
    no servidor, como no servidor para evitar os seguintes ataques:
    - ***Path traversal***: O servidor valida os caminhos dos ficheiros, evitando
        que um cliente aceda a ficheiros fora do seu cofre seguro, bloqueando
        quaisquer tentativas de leitura ou escrita em diretorias para além do
        cofre seguro;
    - **Proteção contra OOM e DoS**: O servidor valida o tamanho de todos os dados recebidos,
        visando combater ataques de *Out of Memory*, que poderiam comprometer dados
        confidenciais do servidor, ou ataques de *Denial of Service* que, em um caso
        de envio de dados excessivos e/ou constantes, poderiam levar à
        sobrecarga do servidor, tornando-o incapaz de atender a outros pedidos, pela
        falta de capacidade de processamento e/ou memória em relação aos metadados;
    - ***Reverse shells***: O servidor em nenhum momento executa comandos nativamente
        no sistema operativo, evitando assim que um cliente possa executar comandos
        maliciosos no servidor, como por exemplo, abrir uma *shell* reversa que
        sobrepasse possíveis regras de *firewall* definidas ou executar comandos
        de leitura/escrita de ficheiros sensíveis do sistema;
- ***Atomic writes***: O servidor ao escrever conteúdos no disco, utiliza
    operações atómicas, garantindo que os dados não são corrompidos em caso de falha
    durante a escrita. Para tal, o servidor utiliza um ficheiro temporário para
    escrever os dados e só depois renomeia o ficheiro temporário para o nome final,
    deste modo o servidor garante que mesmo em situações de falha, conteúdos em
    disco, bem como os metadados, não são corrompidos.

## Conclusão

O desenvolvimento do serviço de Cofre Seguro cumpriu os objetivos propostos,
oferecendo uma solução robusta e segura para armazenamento e partilha de ficheiros.
Através da implementação de mecanismos avançados de segurança, como
**encriptação híbrida (AES-GCM e RSA)**, **autenticação baseada em certificados X.509**
e **comunicação protegida por TLS**, garantiu-se a **confidencialidade**, **integridade**
e **autenticidade** dos dados, tanto em trânsito como em repouso.

A arquitetura cliente-servidor, aliada a um sistema de metadados bem estruturado,
permitiu uma gestão eficiente de utilizadores, grupos e ficheiros, com controlo
granular de permissões. A introdução de funcionalidades adicionais ampliou as
capacidades do sistema, tornando-o mais flexível e auditável.

Apesar das limitações inerentes ao tempo e escopo do projeto, a solução desenvolvida
demonstrou ser escalável, podendo ser expandida com melhorias futuras.

Em síntese, este projeto não só cumpriu os requisitos técnicos e de segurança definidos,
como também serviu como uma aplicação prática dos conceitos teóricos abordados na
unidade curricular, reforçando a importância de uma abordagem rigorosa no
desenvolvimento de sistemas seguros.
