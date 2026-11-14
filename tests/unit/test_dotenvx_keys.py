"""Tests for envdrift.integrations.dotenvx_keys: dotenvx's own key rules, ported.

Every expectation about how dotenvx parses ``.env.keys``, names keys and derives
public keys was first checked against the pinned dotenvx binary (the variants
below decrypt, or fail to, with ``dotenvx get -fk``); the integration suite
(tests/integration/test_dotenvx_key_reuse.py) re-checks the important ones
against the real binary at test time.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.integrations.dotenvx_keys import (
    KeyReuseError,
    KeyTarget,
    assignment_line_pattern,
    assignment_values,
    distinct_keys,
    dotenvx_environment,
    dotenvx_key_names,
    has_encrypted_values,
    held_key_problem,
    key_outcome_problem,
    normalize_public_key,
    parse_assignments,
    plan_key_reuse,
    private_key_candidates,
    private_key_scalar,
    public_key_for,
    public_key_values,
    seed_public_key,
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


# --- seeding the header dotenvx itself would write -----------------------------


def test_seed_public_key_writes_the_dotenvx_header(tmp_path: Path):
    env_file = tmp_path / ".env.prod"
    seeded = seed_public_key("A=1\n", env_file, tmp_path / ".env.keys", PUB1)
    assert seeded == (
        "#/-------------------[DOTENV_PUBLIC_KEY]--------------------/\n"
        "#/            public-key encryption for .env files          /\n"
        "#/       [how it works](https://dotenvx.com/encryption)     /\n"
        "#/----------------------------------------------------------/\n"
        f'DOTENV_PUBLIC_KEY_PROD="{PUB1}"\n'
        "\n"
        "# .env.prod\n"
        "A=1\n"
    )


def test_seed_public_key_keeps_a_shebang_first_and_names_a_custom_keys_file(tmp_path: Path):
    env_file = tmp_path / ".env.production"
    seeded = seed_public_key("#!/bin/sh\nA=1", env_file, tmp_path / ".secrets.keys", PUB1)
    lines = seeded.split("\n")
    assert lines[0] == "#!/bin/sh"
    assert lines[5] == f'DOTENV_PUBLIC_KEY_PRODUCTION="{PUB1}" # -fk .secrets.keys'
    assert lines[-1] == "A=1"


# --- planning: reuse the held key or refuse (#938, B4) -------------------------


def _plan(env_text: str, keys_text: str | None, tmp_path: Path, name: str = NAME):
    return plan_key_reuse(
        env_text,
        keys_text,
        KeyTarget(tmp_path / ".env.production", tmp_path / ".env.keys", name),
    )


def test_plan_without_a_held_key_changes_nothing(tmp_path: Path):
    plan = _plan("A=1\n", "DOTENV_PRIVATE_KEY_STAGING=" + K2 + "\n", tmp_path)
    assert plan.held_key is None
    assert plan.env_text == "A=1\n"


def test_plan_seeds_the_held_keys_public_key(tmp_path: Path):
    plan = _plan("A=1\n", f"{NAME}={K1}\n", tmp_path)
    assert plan.public_key == PUB1
    assert public_key_values(plan.env_text) == [PUB1]
    assert plan.env_text.endswith("# .env.production\nA=1\n")


def test_plan_keeps_a_matching_header(tmp_path: Path):
    text = f'DOTENV_PUBLIC_KEY_PRODUCTION="{PUB1}"\nA=encrypted:x\nB=new\n'
    assert _plan(text, f"export {NAME} = {K1} # vault\n", tmp_path).env_text == text


def test_plan_rewrites_another_keys_header_while_nothing_is_encrypted(tmp_path: Path):
    text = f'DOTENV_PUBLIC_KEY_PRODUCTION="{PUB2}" # -fk x\nA=plain\n'
    plan = _plan(text, f"{NAME}={K1}\n", tmp_path)
    assert plan.env_text == f'DOTENV_PUBLIC_KEY_PRODUCTION="{PUB1}" # -fk x\nA=plain\n'


def test_plan_refuses_a_file_encrypted_under_another_key(tmp_path: Path):
    text = f'DOTENV_PUBLIC_KEY_PRODUCTION="{PUB2}"\nA=encrypted:abc\nB=new\n'
    with pytest.raises(KeyReuseError, match="encrypted with another public key"):
        _plan(text, f"{NAME}={K1}\n", tmp_path)


def test_plan_refuses_two_different_held_keys(tmp_path: Path):
    with pytest.raises(KeyReuseError, match="holds 2 different keys"):
        _plan("A=1\n", f"{NAME}={K1}\n{NAME}={K2}\n", tmp_path)


def test_plan_refuses_a_comma_list_of_two_keys(tmp_path: Path):
    with pytest.raises(KeyReuseError, match="holds 2 different keys"):
        _plan("A=1\n", f"{NAME}={K1},{K2}\n", tmp_path)


def test_plan_accepts_the_same_key_twice(tmp_path: Path):
    assert _plan("A=1\n", f"{NAME}={K1}\n{NAME}={K1.upper()}\n", tmp_path).held_key == K1


@pytest.mark.parametrize("value", ["zzz_not_hex", ""])
def test_plan_refuses_a_value_dotenvx_cannot_use(tmp_path: Path, value: str):
    """A garbage key fails with what is wrong, not with a "second value" (B2)."""
    with pytest.raises(KeyReuseError, match="is not a valid dotenvx key"):
        _plan("A=1\n", f"{NAME}={value}\n", tmp_path)


def test_plan_refuses_a_header_it_cannot_rewrite(tmp_path: Path):
    """dotenvx reads ``NAME:`` + newline + value; the line rewrite cannot, so refuse."""
    text = f"DOTENV_PUBLIC_KEY_PRODUCTION:\n{PUB2}\nA=plain\n"
    assert public_key_values(text) == [PUB2]
    with pytest.raises(KeyReuseError, match="could not rewrite it safely"):
        _plan(text, f"{NAME}={K1}\n", tmp_path)


# --- after dotenvx: the outcome check (#938) -----------------------------------


def _held_plan(tmp_path: Path):
    return _plan("A=1\n", f"{NAME}={K1}\n", tmp_path)


def test_outcome_holds_when_dotenvx_used_the_held_key(tmp_path: Path):
    plan = _held_plan(tmp_path)
    keys = f"{NAME}={K1}\n"
    assert key_outcome_problem(plan, keys, keys, plan.env_text + "A=encrypted:x\n") is None


def test_outcome_flags_a_second_value_for_the_held_name(tmp_path: Path):
    plan = _held_plan(tmp_path)
    problem = key_outcome_problem(plan, f"{NAME}={K1}\n", f"{NAME}={K1}\n{NAME}={K2}\n", "")
    assert problem == f"dotenvx changed {NAME} in the keys file"


def test_outcome_flags_a_replaced_value(tmp_path: Path):
    plan = _held_plan(tmp_path)
    assert key_outcome_problem(plan, f"{NAME}={K1}\n", f"{NAME}={K2}\n", "") is not None


def test_outcome_flags_any_new_key_name_when_one_was_held(tmp_path: Path):
    plan = _held_plan(tmp_path)
    after = f"{NAME}={K1}\nDOTENV_PRIVATE_KEY_PROD={K2}\n"
    problem = key_outcome_problem(plan, f"{NAME}={K1}\n", after, plan.env_text)
    assert problem == f"dotenvx created DOTENV_PRIVATE_KEY_PROD instead of using {NAME}"


def test_outcome_flags_a_file_left_without_the_held_public_key(tmp_path: Path):
    """No public key after dotenvx is not proof of the held key: never accept it."""
    plan = _held_plan(tmp_path)
    keys = f"{NAME}={K1}\n"
    problem = key_outcome_problem(plan, keys, keys, "A=encrypted:x\n")
    assert problem is not None
    assert "carries no public key" in problem


def test_outcome_flags_another_public_key_when_one_was_held(tmp_path: Path):
    plan = _held_plan(tmp_path)
    keys = f"{NAME}={K1}\n"
    env_after = f'DOTENV_PUBLIC_KEY_PRODUCTION="{PUB2}"\nA=encrypted:x\n'
    assert "another key than" in (key_outcome_problem(plan, keys, keys, env_after) or "")


def test_outcome_accepts_a_minted_key_that_was_saved(tmp_path: Path):
    plan = _plan("A=1\n", None, tmp_path)
    env_after = f'DOTENV_PUBLIC_KEY_PRODUCTION="{PUB2}"\nA=encrypted:x\n'
    assert key_outcome_problem(plan, None, f"{NAME}={K2}\n", env_after) is None


def test_outcome_flags_a_minted_key_that_was_not_saved(tmp_path: Path):
    plan = _plan("A=1\n", None, tmp_path)
    env_after = f'DOTENV_PUBLIC_KEY_PRODUCTION="{PUB2}"\nA=encrypted:x\n'
    problem = key_outcome_problem(plan, None, None, env_after)
    assert problem == "dotenvx encrypted the file with a key it did not save in the keys file"


def test_outcome_accepts_the_teams_public_key_without_a_local_key(tmp_path: Path):
    """Encrypting with a header's public key needs no private key (no false refusal)."""
    text = f'DOTENV_PUBLIC_KEY="{PUB2}"\nA=1\n'
    plan = _plan(text, None, tmp_path, name="DOTENV_PRIVATE_KEY")
    assert key_outcome_problem(plan, None, None, text + "B=encrypted:x\n") is None


def test_outcome_flags_a_second_public_key_prepended_to_the_file(tmp_path: Path):
    text = f'DOTENV_PUBLIC_KEY_LOCAL="{PUB2}"\nA=1\n'
    plan = _plan(text, None, tmp_path)
    env_after = f'DOTENV_PUBLIC_KEY_PRODUCTION="{PUB1}"\n' + text
    problem = key_outcome_problem(plan, None, f"{NAME}={K1}\n", env_after)
    assert problem == "the file now carries two different public keys"


# --- read-only check for encrypted files (lock, B4) ----------------------------


def test_held_key_problem_cases():
    header = f'DOTENV_PUBLIC_KEY_PRODUCTION="{PUB1}"\nA=encrypted:x\n'
    assert held_key_problem(header, f"{NAME}={K1}\n", NAME) is None
    assert held_key_problem(header, None, NAME) is None
    # dotenvx skips a value it cannot use as a key, so nothing could decrypt the file.
    assert "not a valid dotenvx key" in (held_key_problem(header, f"{NAME}=dummy\n", NAME) or "")
    assert "2 different keys" in (held_key_problem(header, f"{NAME}={K1},{K2}\n", NAME) or "")
    assert "another public key" in (held_key_problem(header, f"{NAME}={K2}\n", NAME) or "")
