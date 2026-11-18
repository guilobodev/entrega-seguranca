# Projeto Integrador | Segurança Aplicada ao Desenvolvimento

**Universidade Tiradentes**

**Alunos:** Adriano Santana Fonseca, Guilherme Lôbo Brayner e Luiz Gustavo Santana.

Repositório com as entregas do Projeto Integrador, cada uma em sua própria pasta, com código, testes e documentação.

## Entregas

| Entrega | Tema | Tecnologias | Pasta |
|---|---|---|---|
| 1 | Criptografia assimétrica e confiança | RSA-OAEP (2048 bits) e AES-GCM (256 bits), com `cryptography` | [`entrega1_criptografia`](./entrega1_criptografia) |
| 2 | Hash e autenticação segura | Argon2id e SQLite, com `argon2-cffi` | [`entrega2_autenticacao`](./entrega2_autenticacao) |

## Resumo

- **Entrega 1:** cifragem híbrida de mensagens entre dois serviços. O conteúdo é cifrado com AES-GCM, a chave AES é protegida com RSA-OAEP, e qualquer adulteração é detectada no destino.
- **Entrega 2:** cadastro e login sem armazenar senhas em texto puro. Usa Argon2id com salt único por usuário, comparação segura feita pela biblioteca e 17 testes automatizados.

## Como executar

Requisito: Python 3.10 ou superior.

**Entrega 1** (rodar a partir da raiz do repositório):
```bash
pip install cryptography
python -m entrega1_criptografia.criptografia_hibrida
python -m unittest entrega1_criptografia/test_entrega1.py
```

**Entrega 2** (rodar de dentro da pasta da entrega):
```bash
cd entrega2_autenticacao
pip install -r requirements.txt
python demo.py
python -m unittest -v test_entrega2.py
```

Detalhes de cada entrega (algoritmos, parâmetros, fluxos, riscos e limitações) estão no README dentro da respectiva pasta.

> Todos os dados usados nas demonstrações (usuários e senhas) são fictícios.
