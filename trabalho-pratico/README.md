# Relatório - Serviço de Cofre Seguro

## Introdução

TODO

## Arquitetura do Serviço

- Imagem descritiva
- Argumentos passados para cada programa
- Módulos do serviço
- Referir o estilo de servidor (semelhante a zero-trust)
TODO

## Comunicação entre Cliente e Servidor

- Utilização do módulo SSL
- Wrapper em volta do socket
- Context do módulo SSL (sem falar muito nos certificados)
- Encriptação envolvida (referindo a garantia de autenticidade, integridade e confidencialidade)
- Formato dos pacotes (header + payload)
- Comunicação sequencial (1 thread por cliente)
TODO

## Autenticação de Clientes e Servidor

- Context do módulo SSL (referindo pormenorizadamente sobre os certificados)
- Validação de certificados (campos)
- Validação de certificados dos dois lados do canal de comunicação (referindo o propósito e os ataques que bloqueia)
- Bloqueio de ataques reply/mitm
- Geração de certificados no lado do servidor
TODO

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

## Possíveis Valorizações

A equipa de trabalho tomou as devidas precauções para garantir uma segurança acrescida
do sistema, das quais se destacam:

- **Validação de certificados**: O servidor valida os certificados dos clientes
    e vice-versa, garantindo que apenas clientes autorizados podem aceder ao serviço,
    bem como são verificadas as assinaturas digitais dos certificados, e respetivas
    datas de validade.
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

TODO
