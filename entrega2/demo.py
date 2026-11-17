"""Demonstracao da Entrega 2: cadastro, banco protegido, login correto/incorreto
e comparacao com SHA-256 isolado. Execute: python demo.py"""
import hashlib
import time

from autenticacao import ErroCadastro, autenticar, cadastrar_usuario, conectar


def main() -> None:
    conexao = conectar("usuarios_demo.db")
    conexao.execute("DELETE FROM usuarios")
    conexao.commit()

    print("=== 1. Cadastro de usuarios (senhas ficticias) ===")
    cadastrar_usuario(conexao, "alice", "SenhaForte#2026-A")
    cadastrar_usuario(conexao, "bob", "SenhaForte#2026-A")  # mesma senha de proposito
    print("Usuarios 'alice' e 'bob' cadastrados com a MESMA senha.")

    print("\n=== 2. Conteudo do banco (nenhuma senha em texto puro) ===")
    for nome, senha_hash in conexao.execute("SELECT nome_usuario, senha_hash FROM usuarios"):
        print(f"{nome:6} -> {senha_hash}")
    print("Hashes diferentes mesmo com senhas iguais: o salt e unico por usuario.")

    print("\n=== 3. Login correto e incorreto ===")
    casos = [
        ("alice", "SenhaForte#2026-A", "senha correta"),
        ("alice", "SenhaErrada#999999", "senha incorreta"),
        ("fantasma", "SenhaForte#2026-A", "usuario inexistente"),
    ]
    for usuario, senha, descricao in casos:
        r = autenticar(conexao, usuario, senha)
        print(f"{descricao:20} -> sucesso={r.sucesso} | {r.motivo}")

    print("\n=== 4. Validacao de entrada ===")
    for usuario, senha in [("alice", "OutraSenha#2026-B"), ("carol", "curta")]:
        try:
            cadastrar_usuario(conexao, usuario, senha)
        except ErroCadastro as erro:
            print(f"Cadastro recusado ({usuario}): {erro}")

    print("\n=== 5. Custo: SHA-256 isolado vs Argon2id ===")
    inicio = time.perf_counter()
    for _ in range(1000):
        hashlib.sha256(b"SenhaForte#2026-A").hexdigest()
    t_sha = (time.perf_counter() - inicio) / 1000
    inicio = time.perf_counter()
    autenticar(conexao, "alice", "SenhaForte#2026-A")
    t_argon = time.perf_counter() - inicio
    print(f"SHA-256: {t_sha * 1e6:.2f} microssegundos por tentativa")
    print(f"Argon2id: {t_argon * 1e3:.1f} milissegundos por tentativa")
    print(f"Razao aproximada: {t_argon / t_sha:,.0f}x mais lento para quem tenta adivinhar senhas.")
    conexao.close()


if __name__ == "__main__":
    main()
