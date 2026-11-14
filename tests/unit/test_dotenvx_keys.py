"""Tests for envdrift.integrations.dotenvx_keys: dotenvx's own key rules, ported.

Every expectation about how dotenvx parses ``.env.keys``, names keys and derives
public keys was first checked against the pinned dotenvx binary (the variants
below decrypt, or fail to, with ``dotenvx get -fk``); the integration suite
(tests/integration/test_dotenvx_key_reuse.py) re-checks the important ones
against the real binary at test time.
"""

from __future__ import annotations

import pytest

from envdrift.integrations.dotenvx_keys import (
    assignment_line_pattern,
    assignment_values,
    distinct_keys,
    dotenvx_environment,
    dotenvx_key_names,
    has_encrypted_values,
    normalize_public_key,
    parse_assignments,
    private_key_candidates,
    private_key_scalar,
    public_key_for,
    public_key_values,
)
from tests.helpers import DOTENVX_KEY_PAIRS

K1, PUB1 = DOTENVX_KEY_PAIRS[0]
K2, PUB2 = DOTENVX_KEY_PAIRS[1]
NAME = "DOTENV_PRIVATE_KEY_PRODUCTION"
BOM = chr(0xFEFF)


# --- public keys: plain secp256k1 arithmetic, checked against dotenvx ---------


@pytest.mark.parametrize(("private_key", "public_key"), DOTENVX_KEY_PAIRS)
def test_public_key_for_matches_dotenvx_generated_pairs(private_key: str, public_key: str):
    assert public_key_for(private_key) == public_key


@pytest.mark.parametrize(
    ("spelling", "valid"),
    [
        pytest.param(K1.upper(), True, id="uppercase-hex"),
        pytest.param(K1 + "zz", True, id="node-hex-stops-at-first-bad-pair"),
        pytest.param(K1 + "a", True, id="node-hex-drops-odd-digit"),
        pytest.param("0x" + K1, False, id="0x-prefix"),
        pytest.param(K1[:-2], False, id="short"),
        pytest.param(K1 + "ab", False, id="33-bytes"),
        pytest.param("0" * 64, False, id="zero-scalar"),
        pytest.param("zzz_not_hex", False, id="garbage"),
        pytest.param("", False, id="empty"),
    ],
)
def test_private_key_accepted_exactly_like_dotenvx(spelling: str, valid: bool):
    """dotenvx uses ``new PrivateKey(Buffer.from(hex, "hex"))``; mirror its verdicts."""
    assert (private_key_scalar(spelling) is not None) is valid
    if valid:
        assert public_key_for(spelling) == PUB1
    else:
        with pytest.raises(ValueError, match="not a valid dotenvx private key"):
            public_key_for(spelling)


def test_normalize_public_key_compresses_uncompressed_form():
    # 04 || x || y for the first pair: its y is odd (prefix 03).
    x_hex = PUB1[2:]
    from envdrift.integrations.dotenvx_keys import _P

    x = int(x_hex, 16)
    y_squared = (pow(x, 3, _P) + 7) % _P
    y = pow(y_squared, (_P + 1) // 4, _P)
    if y % 2 == 0:  # pick the odd root, as the compressed prefix 03 says
        y = _P - y
    uncompressed = "04" + x_hex + format(y, "064x")
    assert normalize_public_key(uncompressed.upper()) == PUB1
    assert normalize_public_key("pub") == "pub"


# --- the .env.keys parser is dotenvx's scanner (S2) ----------------------------


@pytest.mark.parametrize(
    "line",
    [
        pytest.param(f"{NAME}={K1}", id="plain"),
        pytest.param(f"{BOM}{NAME}={K1}", id="utf8-bom"),
        pytest.param(f"export {NAME}={K1}", id="export"),
        pytest.param(f"{NAME} = {K1}", id="spaces-around-equals"),
        pytest.param(f"{NAME}= {K1}", id="space-after-equals"),
        pytest.param(f"{NAME}={K1} # team key", id="inline-comment"),
        pytest.param(f"{NAME}={K1}#c", id="comment-without-space"),
        pytest.param(f"   {NAME}={K1}", id="leading-spaces"),
        pytest.param(f"\t{NAME}={K1}", id="leading-tab"),
        pytest.param(f'{NAME}="{K1}"', id="double-quotes"),
        pytest.param(f"{NAME}='{K1}'", id="single-quotes"),
        pytest.param(f"{NAME}=`{K1}`", id="backticks"),
        pytest.param(f'{NAME}="{K1}" # c', id="quoted-with-comment"),
        pytest.param(f"{NAME}: {K1}", id="colon-form"),
    ],
)
def test_parser_reads_the_key_where_dotenvx_does(line: str):
    """Each line form decrypts with ``dotenvx get -fk`` in the pinned binary."""
    assert assignment_values(f"# header\n{line}\n", NAME) == [K1]


def test_parser_keeps_every_value_of_a_repeated_name_in_order():
    text = f"{NAME}={K1}\r\n# comment\r\n{NAME}={K2}\r\n"
    assert assignment_values(text, NAME) == [K1, K2]


def test_parser_does_not_read_a_lowercase_or_commented_name():
    text = f"dotenv_private_key_production={K1}\n# {NAME}={K2}\n"
    assert assignment_values(text, NAME) == []


def test_parser_empty_value_and_escapes():
    parsed = parse_assignments("A=\nB=\"x\\ny\"\nC='it\\'s'\n")
    assert parsed == {"A": [""], "B": ["x\ny"], "C": ["it's"]}


def test_private_key_candidates_split_like_the_dotenvx_key_ring():
    assert private_key_candidates([f"{K1},{K2}", K1]) == [K1, K2, K1]


def test_distinct_keys_treats_two_spellings_of_one_key_as_one():
    assert distinct_keys([K1, K1.upper(), K2, K1 + "zz"]) == [K1, K2]


def test_assignment_line_pattern_matches_reader_forms_only():
    pattern = assignment_line_pattern(NAME)
    assert pattern.match(f"{BOM}export {NAME} = x")
    assert pattern.match(f"{NAME}: x")
    assert not pattern.match(f"# {NAME}=x")
    assert not pattern.match(f"{NAME}_OTHER=x")


def test_public_key_values_and_encrypted_values():
    text = f'DOTENV_PUBLIC_KEY_PRODUCTION="{PUB1}" # -fk keys\nA=encrypted:abc\nB=plain\n'
    assert public_key_values(text) == [PUB1]
    assert has_encrypted_values(text)
    assert not has_encrypted_values(f'DOTENV_PUBLIC_KEY="{PUB1}"\nA=plain\n')


# --- key names exactly as dotenvx derives them (N1) ----------------------------


@pytest.mark.parametrize(
    ("filename", "suffix"),
    [
        (".env", None),
        (".env.txt", None),
        (".env.production", "PRODUCTION"),
        (".env.Production", "PRODUCTION"),
        (".ENV.Staging", "STAGING"),
        (".env.production.txt", "PRODUCTION"),
        (".env.prod.eu", "PROD_EU"),
        (".env.prod.eu.west", "PROD_EU"),
        (".env.a.b.c.d", "A_B"),
        ("config.env.prod", "PROD"),
        ("secrets.env", "SECRETSDEVELOPMENT"),
        ("postgresql.env", "POSTGRESQLDEVELOPMENT"),
        (".env-prod", "DEVELOPMENT-PROD"),
    ],
)
def test_dotenvx_key_names_match_the_binary(filename: str, suffix: str | None):
    """Each name is what the pinned dotenvx minted for that filename."""
    public, private = dotenvx_key_names(filename)
    if suffix is None:
        assert (public, private) == ("DOTENV_PUBLIC_KEY", "DOTENV_PRIVATE_KEY")
    else:
        assert public == f"DOTENV_PUBLIC_KEY_{suffix}"
        assert private == f"DOTENV_PRIVATE_KEY_{suffix}"


def test_dotenvx_environment_is_lowercase():
    assert dotenvx_environment(".env.PROD.eu.West") == "prod_eu"
