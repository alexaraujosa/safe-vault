# Metadata

## Objetivo

A metadata é uma componente essencial do sistema de Cofre Seguro, responsável por
armazenar todas as informações necessárias para o funcionamento do serviço, incluindo:

- Dados dos utilizadores e as suas chaves públicas RSA;
- Informações sobre ficheiros armazenados;
- Estrutura de grupos e respetivas permissões;
- Relações de partilha e controlo de acesso.

Em conjunto com o módulo `server.operations`, esta garante o controlo de
acesso e gestão segura dos recursos do sistema. É persistida em formato JSON
no fim da execução do servidor e carregado automaticamente aquando da sua
inicialização.

## Vantagens

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

## Estrutura

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
          "key": "encrypted_key",      // Chave simétrica AES encriptada com a chave privada RSA
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
            "key": "encrypted_key"     // Chave simétrica AES encriptada com a chave privada RSA
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
                                         // chave privada RSA do membro codificada em base64
        }
      },
      "files": {
        "<user_id>": ["file.txt"]      // Lista de ficheiros no grupo do dado membro
      }
    }
  }
}
```

## Notas

1. **Identificadores Únicos**:
    - `user_id`: Nome de utilizador, único e imutável, obtido através do campo
        `PSEUDONYM` do certificado X.509;
    - `file_id`: Segue o formato `user_id:filename`, onde `user_id` é o ID do dono
        do ficheiro e `filename` o nome (*basename*) do ficheiro;
    - `group_id`: Nome do grupo, único e imutável, definido pelo dono na sua criação.

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
