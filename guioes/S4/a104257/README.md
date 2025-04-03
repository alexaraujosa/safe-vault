# Guião 02

> Q2: Qual o impacto de se considerar um NONCE fixo (e.g. tudo 0)?
> Que implicações terá essa prática na segurança da cifra?

O NONCE deve ser único para cada mensagem encriptada. Se for fixo, permite
ataques de repetição e pode comprometer a segurança da cifra, especialmente
em modos de operação que dependem da unicidade do NONCE para garantir a
aleatoriedade do processo de cifragem.

> Q3: Qual o impacto de utilizar o programa `chacha20_int_attck.py` nos criptogramas
> produzidos pelos programas `cfich_aes_cbc.py` e `cfich_aes_ctr.py`?
> Comente/justifique a resposta.

O ataque afeta AES-CTR, pois, como ChaCha20, é um cifrador de fluxo e permite
modificações previsíveis no texto decifrado.
Já AES-CBC não é vulnerável da mesma forma, pois alterações no criptograma
propagam erros para os blocos seguintes.
