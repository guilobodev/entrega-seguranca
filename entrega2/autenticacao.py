"""Entrega 2 - Hash e autenticacao segura.

Cadastro e login de usuarios sem armazenar senhas em texto puro.
Usa Argon2id (biblioteca argon2-cffi) e SQLite com consultas parametrizadas.
Nenhum algoritmo criptografico proprio e implementado.
"""
import re
import sqlite3
from dataclasses import dataclass

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# Parametros Argon2id: perfil "segunda opcao recomendada" da RFC 9106
# (t=3, m=64 MiB, p=4), acima do minimo da OWASP Password Storage Cheat Sheet
# (m=19 MiB, t=2, p=1). Salt de 16 bytes gerado automaticamente pela biblioteca
# (os.urandom) para cada senha; hash de saida de 32 bytes.
PARAMETROS_ARGON2 = {
    "time_cost": 3,
    "memory_cost": 64 * 1024,  # em KiB -> 64 MiB
    "parallelism": 4,
    "hash_len": 32,
    "salt_len": 16,
    "type": Type.ID,
}

SENHA_MIN = 12
SENHA_MAX = 128  # limite para evitar DoS por senhas gigantes
REGEX_USUARIO = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

# Hash "isca" usado para igualar o tempo de resposta quando o usuario nao existe
# (mitiga enumeracao de usuarios por tempo de resposta).
_HASHER = PasswordHasher(**PARAMETROS_ARGON2)
_HASH_ISCA = _HASHER.hash("senha-isca-nao-utilizada")


class ErroCadastro(ValueError):
    """Dados de cadastro invalidos ou usuario ja existente."""


@dataclass
class ResultadoLogin:
    sucesso: bool
    motivo: str = ""


def conectar(caminho: str = ":memory:") -> sqlite3.Connection:
    conexao = sqlite3.connect(caminho)
    conexao.execute(
        """
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome_usuario TEXT NOT NULL UNIQUE,
            senha_hash TEXT NOT NULL,
            criado_em TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conexao.commit()
    return conexao


def validar_senha(senha: str) -> None:
    if len(senha) < SENHA_MIN:
        raise ErroCadastro(f"A senha deve ter pelo menos {SENHA_MIN} caracteres.")
    if len(senha) > SENHA_MAX:
        raise ErroCadastro(f"A senha deve ter no maximo {SENHA_MAX} caracteres.")


def cadastrar_usuario(conexao: sqlite3.Connection, nome_usuario: str, senha: str) -> None:
    if not REGEX_USUARIO.match(nome_usuario):
        raise ErroCadastro("Nome de usuario invalido (3-32 caracteres: letras, numeros, _ . -).")
    validar_senha(senha)

    # O salt aleatorio de 16 bytes e gerado pela biblioteca e fica embutido
    # na propria string do hash ($argon2id$v=19$m=...,t=...,p=...$salt$hash).
    senha_hash = _HASHER.hash(senha)
    try:
        conexao.execute(
            "INSERT INTO usuarios (nome_usuario, senha_hash) VALUES (?, ?)",
            (nome_usuario, senha_hash),
        )
        conexao.commit()
    except sqlite3.IntegrityError as erro:
        raise ErroCadastro("Usuario ja cadastrado.") from erro


def autenticar(conexao: sqlite3.Connection, nome_usuario: str, senha: str) -> ResultadoLogin:
    linha = conexao.execute(
        "SELECT id, senha_hash FROM usuarios WHERE nome_usuario = ?", (nome_usuario,)
    ).fetchone()

    if linha is None:
        # Executa uma verificacao de mesmo custo para nao revelar a inexistencia do usuario.
        try:
            _HASHER.verify(_HASH_ISCA, senha)
        except (VerificationError, InvalidHashError):
            pass
        return ResultadoLogin(False, "Usuario ou senha invalidos.")

    id_usuario, senha_hash = linha
    try:
        # verify() compara o hash recalculado de forma segura (tempo constante)
        # dentro da biblioteca; nunca comparamos strings de hash com ==.
        _HASHER.verify(senha_hash, senha)
    except VerifyMismatchError:
        return ResultadoLogin(False, "Usuario ou senha invalidos.")
    except (VerificationError, InvalidHashError):
        return ResultadoLogin(False, "Usuario ou senha invalidos.")

    # Rehash transparente se os parametros do sistema foram reforcados.
    if _HASHER.check_needs_rehash(senha_hash):
        conexao.execute(
            "UPDATE usuarios SET senha_hash = ? WHERE id = ?",
            (_HASHER.hash(senha), id_usuario),
        )
        conexao.commit()
    return ResultadoLogin(True, "Login realizado com sucesso.")
