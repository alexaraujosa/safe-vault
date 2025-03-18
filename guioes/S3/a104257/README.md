# Guião 01

## 1. Tarefas preliminares

> Q1: Qual a versão da biblioteca `cryptography` instalada?

41.0.7

## 2. Cifras clássicas

> Q1: Consegue observar diferenças no comportamento dos programas `otp.py` e
`bad_otp.py`? Se sim, quais?

À primeira vista, não se nota diferenças nos *outputs* dos dois programas, ambos
utilizam o algoritmo OTP com a operação XOR para cifrar e decifrar. No entanto,
após analisar as diferenças na geração das chaves, conclui-se que:
- `otp.py` utiliza a função `os.urandom` para gerar a chave de forma segura;
- `bad_otp.py` utiliza a função `random.randint` para gerar a *seed* assim como a chave,
contudo a *seed* gerada é de apenas 2 bytes, o que é extremamente inseguro, uma vez que
apenas existem 2^16 (65536) combinações possíveis, o que, após conhecimento do tamanho
da mensagem, torna a cifra facilmente quebrável.

> Q2: O ataque realizado no ponto anterior não entra em contradição com o
resultado que estabelece a "segurança absoluta" da cifra *one-time pad*?
Justifique.

Não, a cifra *one-time pad* é segura desde que a chave seja aleatória, única e
nunca seja reutilizada. No entanto, o ataque realizado no ponto anterior
demonstra que, ao utilizar uma chave gerada de forma previsível, a cifra
torna-se facilmente quebrável.
