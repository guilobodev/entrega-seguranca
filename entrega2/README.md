# Entrega 2 - Hash e autenticação segura
## Alunos: Adriano Santana Fonseca, Guilherme Lôbo Brayner e Luiz Gustavo Santana.

## Problema e objetivo
Uma aplicação precisa cadastrar usuários sem armazenar senhas em texto puro. Foi implementado um fluxo de cadastro e login com **Argon2id**, armazenando apenas o hash (com salt embutido) em um banco SQLite.

## Ambiente e tecnologias
- Python 3.13, SQLite (módulo `sqlite3` da biblioteca padrão)
- `argon2-cffi` (binding da implementação de referência do Argon2)
- Testes com `unittest`

## Algoritmo, parâmetros e justificativa
| Item | Valor | Justificativa |
|---|---|---|
| Algoritmo | Argon2id | Vencedor da Password Hashing Competition; recomendado pela OWASP e pela RFC 9106; resiste a ataques por GPU (memory-hard) e a side-channels |
| Memória (m) | 64 MiB | Perfil da RFC 9106 (segunda opção); acima do mínimo OWASP (19 MiB) |
| Iterações (t) | 3 | Idem |
| Paralelismo (p) | 4 | Idem |
| Salt | 16 bytes aleatórios, único por senha | Gerado pela biblioteca; fica embutido na string do hash |
| Hash | 32 bytes | Padrão da biblioteca |

Formato armazenado: `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`

## Fluxo
**Cadastro:** valida usuário (regex) e senha (12 a 128 caracteres) → Argon2id gera salt e hash → `INSERT` parametrizado → apenas o hash é gravado.

**Login:** busca usuário (consulta parametrizada) → `PasswordHasher.verify()` recalcula e compara em tempo constante dentro da biblioteca → mensagem genérica em qualquer falha → se os parâmetros do sistema foram reforçados, o hash é regravado (`check_needs_rehash`).

## Por que SHA-256 isolado não é adequado para senhas
- É **rápido de propósito**: uma GPU calcula bilhões de SHA-256 por segundo, permitindo força bruta e dicionário em escala. Na demonstração, SHA-256 leva ~0,3 µs por tentativa contra ~115 ms do Argon2id (mais de 300 mil vezes).
- É **determinístico e sem salt**: a mesma senha gera sempre o mesmo hash, o que permite rainbow tables e revela usuários com senhas iguais.
- Não tem **parâmetros de custo** ajustáveis, portanto não acompanha a evolução do hardware.

## Comparação segura
A verificação é feita exclusivamente por `PasswordHasher.verify()`, que recalcula o hash com o salt e parâmetros do registro e compara internamente em tempo constante. O código nunca compara hashes com `==`. Para usuário inexistente, um hash isca é verificado para igualar o tempo de resposta, e a mensagem de erro é idêntica à de senha incorreta (evita enumeração de usuários).

## Riscos, limitações e melhorias
- Sem limite de tentativas / bloqueio temporário (risco de força bruta online) → adicionar rate limiting e CAPTCHA.
- Sem MFA nem fluxo de recuperação de senha → adicionar TOTP e recuperação segura.
- Sem verificação de senhas vazadas (ex.: Have I Been Pwned) nem política de complexidade além do tamanho.
- Sem *pepper* (segredo do servidor fora do banco) → guardar em cofre de segredos/KMS.
- Aplicação de demonstração em linha de comando, sem TLS nem gerenciamento de sessão.

## Como executar
```bash
cd entrega2_autenticacao
pip install -r requirements.txt
python demo.py                      # demonstração (gera a saída de evidencia_demo.txt)
python -m unittest -v test_entrega2.py   # 17 testes (saída em evidencia_testes.txt)
```

## Evidências
- `evidencia_demo.txt`: cadastro, conteúdo do banco (somente hashes), logins correto/incorreto.
- `evidencia_testes.txt`: execução dos 17 testes (todos OK).
- `Documentacao_Entrega2.docx`: documentação técnica em formato ABNT com capa e contracapa.

## Referências
- OWASP. *Password Storage Cheat Sheet*.
- BIRYUKOV, A.; DINU, D.; KHOVRATOVICH, D.; JOSEFSSON, S. *Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications*. RFC 9106, 2021.
- Documentação oficial do `argon2-cffi`.
