# Guião 03

> Q1: Qual o impacto de executar o programa `chacha20_int_attck.py` sobre um criptograma
produzido por `pbenc_chacha20_poly1305.py`? Justifique.

Tal ataque ao criptograma produzido pelo algoritmo ChaCha20_Poly1305 irá resultar
numa *Authentication Tag* inválida, tornando imediatamente óbvio que o criptograma
foi modificado após a sua geração, dado que a *Authentication Tag* é um MAC gerado
a partir de todo o conteúdo, e o ataque modifica secções da cifra sem reencriptação,
invalidando-a no processo.

> Q2: Qual o motivo da sugestão de usar `m2` com mais de 16 byte? Será possível contornar essa limitação?

É necessário que `m2` tenha um tamanho superior a 16 bytes para que sejam gerados
pelo menos um bloco cifrado seguido de um bloco cifrado final, que servirá para
a *Authentication Tag* vulnerável. Desse modo, é possível criar uma mensagem `m3`
a custa de `m1` e `m2`, ao utilizar o bloco inicial de `m2` conjuntamente com o
bloco final de `m1` através de um XOR para concatenar as mensagens de modo a que
a *Authentication Tag* de `m2` valide a integridade de `m3`, dado que:

- Assume-se uma versão simplificada do algoritmo AES-CBC-MAC, $A_i = E_K^-(P_i ⊕ A_{i-1})$,
onde:
  - $A_i$ é o próximo bloco cifrado;
  - $E_K^-$ é a função de cifra com a chave privada;
  - $P_i$ é o bloco de 16 bytes de texto-fonte;
  - $A_{i-1}$ é o bloco cifrado anterior.
- Sejam $M_{1_f}$ o bloco cifrado final de `m1` e $M_2$ os blocos cifrados de `m2`.
- Seja $C = M_{2_1} ⊕ M_{1_f}$ o bloco de concatenação de `m1` e `m2`.
- $M_3$ é dado pelos blocos cifrados de `m1`. O próximo bloco de `m3`, $M_{3_k}$,
é dado por $A_k = E_K^-(C ⊕ A_{k-1})$. Substituindo, tem-se $A_k = E_K^-((M_{2_1} ⊕ M_{1f}) ⊕ M_{1_f})$.
Ora, uma operação XOR de um valor `A` com um outro dado valor `B` seguida novamente
de uma operação XOR com `B` anulam-se mutuamente, resultando em `A`, logo $A_k = E_K^-(M_{2_1})$,
efetivamente revertendo o MAC de volta ao valor inicial do algoritmo, dado que o
IV inicial ($A_0$) é nulo e $A_k = E_K^-(M_{2_1}) \equiv A_k = E_K^-(M_{2_1} ⊕ A_0)$.
Logo, o bloco cifrado final de `m3` será igual ao bloco final de `m2`.

Caso `m2` tivesse menos de 16 bytes, apenas um bloco cifrado seria gerado, sendo
utilizado para anular o MAC até ao momento. Porém, sem um segundo bloco de cifra
para agir como um novo MAC, a verificação da integridade irá falhar, dado que o
bloco final será unicamente o MAC de `m2`.
