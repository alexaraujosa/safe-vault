## Comunicação entre cliente e servidor

A comunicação entre o cliente e o servidor foi implementada com recurso aos módulos *built-in* do python `ssl` e 
`socket`, em adição aos módulos `cryptography` e `pymongo`.

A comunicação é estabelecida através de sockets TCP, cujo controlo é passado a um contexto SSL configurado para usar o
protocolo `TLSv1.3` e negociar automaticamente os pares AEAD `(AC,AH)` (onde `AC` é o Algoritmo de Cifragem e `AH` é o 
Algoritmo de *Hashing*) a serem usados durante a sessão, entre os disponíveis no sistema pertencentes á lista 
(`AES_128_GCM`, `SHA256`), (`AES_256_GCM`, `SHA384`), (`ChaCha20_Poly1305`, `SHA256`). A troca de chaves no *handshake*
inical é efetuada utilizando o algoritmo de troca de chaves *Elliptic-Curve Diffie-Hellman Ephemeral* utilizando uma das
curvas `x25519`, `secp256r1`, `x448`, negociadas ao mesmo tempo que os pares AEAD.

### *TLS Handshake*
O *handshake* ocorre como definido na norma `TLSv1.3`, salvo o uso das funções de `Early Data` e `Encrypted Extensions`:
1. O cliente envia um pacote `ClientHello`, contendo a lista de pares AEAD que o mesmo suporta, as curvas que suporta para
o algoritmo *ECDHE*.
2. O servidor envia um pacote `ServerHello`, contendo o par AEAD e a curva que selecionou para utilizar na comunicação, 
juntamente com o seu certificado, bem como o certificado `VAULT_CA`. Neste ponto, o servidor e o cliente derivam, 
através do algoritmo *ECDHE*, as chaves de encriptação unidirecionais para o resto do *handshake*, `SERVER_HANDSHAKE_TRAFFIC_SECRET` e `CLIENT_HANDSHAKE_TRAFFIC_SECRET`. Os certificados do pacote  `ServerHello` já se 
encontram encriptados pelo `SERVER_HANDSHAKE_TRAFFIC_SECRET`.
3. O cliente envia pacote com o seu próprio certificado, e também o certificado `VAULT_CA`.
4. O servidor envia um pacote `NewSessionTicker`, invalidando as chaves `SERVER_HANDSHAKE_TRAFFIC_SECRET` e `CLIENT_HANDSHAKE_TRAFFIC_SECRET`. Neste ponto, o servidor e o cliente derivam novas chaves de encriptação 
unidirecionais, válidas para o resto da comunicação, `SERVER_TRAFFIC_SECRET_0` e `CLIENT_TRAFFIC_SECRET_0`.

### Tratamento de Conexões
Ao receber uma nova conexão, o servidor cria uma nova thread para receber e tratar todos os pacotes provenientes da 
mesma conexão, sem impedir o servidor de receber novas conexões, ou de responder a conexões existentes. Ao terminar a 
conexão com um cliente, a thread associada á mesma é terminada.

Todos os pacotes após o *handshake* são encriptados utilizando a cifra selecionada durante o mesmo, com as chaves de
cifragem unidirecionais derivadas, `SERVER_TRAFFIC_SECRET_0` e `CLIENT_TRAFFIC_SECRET_0` e autenticadas utilizando o
algoritmo de *hashing* também selecionado durante o *handshake*, garantindo a autenticidade, integridade e 
confidencialidade de todas as mensagens durante o resto da comunicação. Numa futura conexão, todas as chaves são 
regeneradas, de modo a impedir um *Replay Attack* caso um atacante grave o tráfego durante uma sessão.

### Autenticação
A autenticação é efetuada através dos certificados, descritos em mais detalhe na secção 
**Autenticação de clientes e servidor**. Tanto o servidor como o cliente exigem e validam os certificados durante o 
handshake inicial e abortam a comunicação caso os certificados não sejam válidos ou não correspondam aos certificados 
esperados (no caso do cliente, se o certificado recebido pelo "servidor" não for o certificado real do servidor, o 
cliente aborta a conexão unilateralmente. No caso do servidor, se o certificado recebido for o certificado do servidor, 
ele aborta a conexão de forma graciosa, enviando um pacote do tipo `AUTH_FAIL` antes de fechar o socket).

Um certificado é considerado inválido se:
1. Não seguir a estrutura como definida pela norma x509.
2. Não tenha sido assinado pela Entidade de Certificação `VAULT_CA`.
3. A sua data de início de validade ainda não tenha sido ultrapassada.
4. A sua data de término de validade já tenha sido ultrapassada.
5. Não possuír o campo `SUBJECT.PSEUDONYM`.
6. O campo `SUBJECT.PSEUDONYM` não for igual a `VAULT_SERVER`, caso seja recebido pelo cliente.
7. O campo `SUBJECT.PSEUDONYM` for igual a um utilizador existente na base de dados, mas que tenha sido registado com uma
chave pública diferente, caso seja recebido pelo servidor.

O ponto **6** impede que um atacante se consiga fazer passar pelo servidor perante um cliente ao utilizar um certificado
de cliente, válido em todos os pontos exceto o ponto em questão. No entanto, este ataque tem um impacto mínimo na
confidencialidade dos dados do cliente perante o servidor real, dado que o atacante não conseguiria ler os dados 
enviados pelo servidor ao cliente, mesmo que servisse de *proxy*, dado não possuír a chave privada do cliente.

O ponto **7** impede que um atacante se consiga fazer passar por um outro cliente ao obter um certificado com o mesmo id
de utilizador de um outro cliente de modo ilícito, porém com uma chave pública diferente da original. Este ataque, 
apesar de não conseguir comprometer a confidencialidade dos dados pertencentes ao cliente alvo já existentes no seu 
vault por si só, dado não possuír a chave privada do cliente, podia ainda assim comprometer a integridade dos dados, 
dado conseguir eliminar ficheiros do vault. Porém, não é possível partilhar o ficheiro com outros utilizadores, 
comprometendo a confidencialidade, dado que o criptograma contendo a chave de cifragem do ficheiro foi encriptado com a 
chave privada do cliente alvo, á qual o atacante não tem acesso. Pode, no entanto, "partilhar" o ficheiro na mesma, 
resultando num criptograma inválido.

Dado que os certificados em si são utilizados como meio de autenticação e autorização, torna-se impossível executar um
ataque *Man-In-The-Middle*, já que o atacante só terá acesso aos seus próprios ficheiros caso use um outro certificado, 
e é-lhe impossível ler as mensagens transmitidas caso use o certificado do cliente, dado não possuír a chave privada do
cliente.

### Estrutrura do Pacote
Os pacotes transmitidos entre o servidor e o cliente são dicionários nativos do python serializados através do formato
BSON, disponibilizado pelo módulo `pymongo`. Todos os pacotes seguem a mesma estrutura geral:
| Chave     | Tipo         | Descrição                                                                   |
|:----------|:-------------|:----------------------------------------------------------------------------|
| `version` | `uint32`     | A versão da estrutura dos pacotes utilizada. Versão atual: `1`              |
| `type`    | `PacketType` | O tipo de pacote recebido. Afeta o processador a utilizar para o `payload`. |
| `payload` | `Document`   | O corpo do pacote em si. A sua estrutura depende do tipo de pacote.         |

Uma classe de pacotes, ditos de controlo, possúi uma estrutura fixa e é potencialmente utilizada por qualquer operação:
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
`LOGS_GLOBAL`, `LOGS_GROUP_OWNER`, `LOGS_FILE`, `LOGS_GROUP`) possúem `payloads` dinâmicos controlados pelos operadores 
tanto do cliente como do servidor.

## Autenticação de clientes e servidor
A autenticação durante a comunicação é baseada em torno de certificados extraídos a partir de keystores no formato 
`PKCS12`. Tanto o servidor como cada cliente possúem os seus próprios keystores privados, que contêm a sua 
identificação.

### Keystore
As keystores são ficheiros no formato `PKCS12` que contém uma chave privada assimétrica, um certificado associado á 
chave publica, par da chave privada anterior, e o certificado da Entidade de Certificação `VAULT_CA`. As keystores são 
geradas com recurso ao módulo `certutil`, localizado em `server/certutil.py`. Cada keystore contém os dados necessários 
para identificar únicamente uma entidade, pelo que deve em teoria ser mantido privado a qualquer momento. Por limitações
inerentes ao módulo `ssl`, os conteúdos da keystore, nomeadamente o certificado e a chave privada têm que ser gravados 
no disco e passados como `filepath` ao contexto SSL, pelo que se faz uso do módulo *built-in* do python `tempfile` para
criar estes ficheiros temporários.. Esta é uma limitação que não possuí nenhuma alternativa conhecida 
(ver: https://github.com/python/cpython/issues/60691).

### Certutil
O módulo `certutil.py` foi criado para facilitar a criação de Certificados de Entidades de Certificação Auto-Assinados e
Keystores. 
- O comando `genca` permite gerar um certificado para uma Entidade de Certificação (por defeito `VAULT_CA`), 
conjuntamente com a sua chave privada, necessária para a criação dos certificados utilizados nas Keystores. 
- O comando `genstore` permite gerar uma keystore associada a um dado id e nome de utilizador, com uma data de 
expiração.

Todos os certificados possúem os seguintes campos em comum:
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

> Adicionalmente, o Certificado da Entidade de Certificação tem uma data de expiração fixa de 365 dias a partir da data de 
geração.

Os Certificado das Keystores possúem adicionalmente os seguintes campos:
| Chave         | Valor                |
|:--------------|----------------------|
| `COMMON_NAME` | O nome do utilizador |
| `PSEUDONYM`   | O id do utilizador   |

Todas as chaves são geradas utilizando o algoritmo `RSA2048`, com um exponente público fixo `65537`. Foi ponderado o uso
de chaves de criptografia assimétrica de Curvas Elípticas, porém, dado as chaves serem também utilizadas para a 
encriptação de dados, foi decidido ultimamente utilizar o algoritmo `RSA`, apesar das chaves CE serem menores em 
tamanho. No entanto, uma possível melhoria seria migrar a cifragem de dados para utilizar um algoritmo de cifragem sobre
Curvas Elípticas, como o algoritmo `ElGamal`.