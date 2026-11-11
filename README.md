# Entrega 1 - Criptografia assimétrica e confiança
## Alunos: Adriano Santana Fonseca, Guilherme Lôbo Brayner e Luiz Gustavo Santana.
## Problema e objetivo
Proteger uma mensagem enviada entre dois serviços garantindo que o conteúdo fique cifrado em trânsito e que qualquer adulteração na mensagem seja detectada no destino. Foi implementada a cifragem híbrida com AES-GCM para o conteúdo e RSA-OAEP para encapsular a chave simétrica.

## Algoritmos e parâmetros
Foi utilizada a biblioteca `cryptography` do Python com os seguintes parâmetros:
- **RSA:** chave de 2048 bits e expoente público 65537.
- **RSA-OAEP:** usado para cifrar (encapsular) a chave do AES, configurado com hash SHA-256 e MGF1(SHA-256).
- **AES-GCM:** chave de 256 bits gerada aleatoriamente a cada mensagem e nonce de 12 bytes (96 bits) gerado com `os.urandom(12)`. O modo GCM gera também uma tag de autenticação de 128 bits anexada ao texto cifrado.

## Diferença entre sigilo e autenticidade
- **Sigilo (confidencialidade):** impede que terceiros leiam a mensagem. Na implementação, a mensagem é cifrada com AES-GCM e a chave AES só pode ser aberta pela chave privada RSA do destinatário.
- **Integridade:** garante que a mensagem não foi alterada no caminho. O AES-GCM verifica a tag de autenticação ao decifrar e lança erro (`InvalidTag`) se algum bit for modificado.
- **Autenticidade:** identifica e comprova quem enviou a mensagem. A cifragem sozinha não garante autenticidade do remetente, porque a chave pública do destinatário é aberta e qualquer pessoa que tenha acesso a ela pode cifrar uma mensagem para ele. Para provar quem enviou, seria necessário usar assinatura digital com a chave privada do remetente.

## Função de certificados digitais e PKI
Na criptografia assimétrica, o remetente precisa ter certeza de que a chave pública recebida realmente pertence ao serviço destinatário e não a um invasor no meio da rede (ataque Man-in-the-Middle).
- **Certificado digital:** arquivo eletrônico assinado por uma Autoridade Certificadora (CA) que liga a identidade de um serviço ou domínio à sua chave pública e define uma data de validade.
- **PKI (Infraestrutura de Chaves Públicas):** estrutura formada pelas Autoridades Certificadoras (CA), Autoridades de Registro (RA) e listas de revogação (CRL/OCSP) que emite, valida e revoga certificados digitais.

## Gestão de chaves e limites da solução
- **Gestão de chaves:** a chave AES é gerada apenas em memória para cada mensagem. Já a chave privada RSA não deve ficar salva no código ou no Git; em produção, deve ficar em variáveis de ambiente seguras, cofre de segredos (Vault) ou KMS/HSM.
- **Limites da solução:**
  - Não autentica quem enviou a mensagem, pois implementa apenas a cifragem híbrida sem assinatura digital do remetente.
  - As chaves são usadas diretamente em memória, sem validação de certificado digital por uma CA.
  - Não possui controle de timestamp ou ID único contra reenvio da mesma mensagem cifrada (replay attack).

## Como executar
```bash
pip install cryptography
python -m entrega1_criptografia.criptografia_hibrida
python -m unittest entrega1_criptografia/test_entrega1.py
```
