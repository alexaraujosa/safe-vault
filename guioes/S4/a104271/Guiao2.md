# Questão 2
> Qual o impacto de se considerar um NONCE fixo (e.g. tudo 0)? Que implicações terá essa prática na segurança da cifra?

O uso de um nonce constante implica que a mesma mensagem, para a mesma chave, terá sempre o mesmo criptograma, tornando o algoritmo vulneravel a um ataque passível de derivar a chave a partir da análise de vários criptogramas.

# Questão 3
> Qual o impacto de utilizar o programa chacha20_int_attck.py nos criptogramas produzidos pelos programas cfich_aes_cbc.py e cfich_aes_ctr.py? Comente/justifique a resposta.

Não faz um caralho.