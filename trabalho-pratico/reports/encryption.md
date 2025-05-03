## Encriptação de Ficheiros

Para encriptação de ficheiros a equipa trabalho decidiu utilizar um esquema de
encriptação híbrido, onde a encriptação simétrica é utilizada para encriptar o
ficheiro e a encriptação assimétrica é utilizada para encriptar a chave simétrica.

Este esquema de encriptação híbrido permite uma maior eficiência na encriptação
e desencriptação de ficheiros, uma vez que a encriptação simétrica é mais rápida
que a encriptação assimétrica.

**TODO** adicionar mais vantagens do esquema híbrido.

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

A integridade e confidencialidade dos conteúdos dos ficheiros é garantida
através do uso da encriptação AES-GCM.

**TODO** explicar como o AES-GCM garante a integridade dos dados. (blocos)

Por outro lado, a integridade e confidencialidade das chaves simétricas guardadas
nos metadados do servidor é garantida através do uso da encriptação assimétrica RSA.

**TODO** a equipa de trabalho decidiu utilizar RSA com 2048 bits. (incluir source mistre)

---

**TODO** adicionar nota sobre a reencriptação de chaves e conteúdos em revogações,
explicar o processo em diferentes casos, e o porquê de não o termos feito
(ACL garante + eficiência de revogação). num ambiente de produção deve-se ponderar
esta reencriptação.
