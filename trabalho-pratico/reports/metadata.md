# Metadata

## Objetivo

A metadata é uma componente essencial do sistema de Cofre Seguro, responsável por
armazenar todas as informações necessárias para o funcionamento do serviço, incluindo:

- Dados dos utilizadores e as suas chaves públicas RSA;
- Informações sobre ficheiros armazenados;
- Estrutura de grupos e respetivas permissões;
- Relações de partilha e controlo de acesso.

Esta, em conjunto do módulo `server.operations`, garante o controlo de
acesso e gestão segura dos recursos do sistema. É persistido em formato JSON
no fim da execução do servidor e carregado automaticamente aquando o servidor é
inicializado.

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
    - `user_id`: É o nome de utilizador do utilizador, único e imutável,
        obtido através do campo `COMMON_NAME` do certificado X.509;
    - `file_id`: Segue o formato `user_id:filename`, onde `user_id` é o ID do
        dono do ficheiro e `filename` é o nome (*basename*) do ficheiro;
    - `group_id`: É o nome do grupo, único e imutável, definido pelo dono na sua criação.

2. **Segurança**:
    - Todas as chaves simétricas (AES) são armazenadas encriptadas com a chave privada
        do respetivo utilizador a, futuramente, aceder ao ficheiro, garantindo que
        o servidor não tem acesso a estas chaves e por consequente ao conteúdo dos
        ficheiros;
    - A chave (mestra) simétrica de cada grupo é gerada pelo dono do grupo e é
        encriptada com a chave pública de cada membro, garantindo que apenas os
        membros do grupo podem aceder à chave simétrica dos ficheiros do grupo.

3. **Controlo de Acesso**:
    - Modelo hierárquico de permissões:
        1. **Dono do ficheiro (*owner*)**
            - Permissões completas: ler (`r`), escrever (`w`), apagar e partilhar.
        2. **Acessos concedidos**
            - Partilhas diretas: com permissões atribuídas individualmente;
            - Membros de grupos: herdam as permissões definidas no grupo
                (note que o dono do grupo pode remover um ficheiro do grupo,
                contudo o dono do ficheiro mantém o acesso).
        3. **Outros utilizadores**:
            - Sem quaisquer permissões.
    - O controlo de acesso é gerido através das listas de controlo de acesso (ACL),
        onde cada ficheiro tem uma lista de utilizadores com permissões específicas,
        e, para grupos, as permissões são armazenadas na lista de membros do grupo.

4. **Eficiência**:
    - A estrutura de dados é organizada de forma a minimizar o tempo de pesquisa
        de forma a maximizar a eficiência das operações, existindo assim alguns
        dados redundantes para facilitar a procura de permissões de partilhas e
        quais os grupos a que um ficheiro pertence. O módulo `server.operations`
        é responsável por garantir a consistência desses dados.

No próximo capítulo aprofundar-se-á como o ficheiro de metadata é utilizado
aquando diferentes comandos do cliente são executados, também abordar-se-á
o conceito introduzido de moderador de um grupo e comandos adicionais aos
requisitos providenciados.
