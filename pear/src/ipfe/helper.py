from sage.arith.misc import inverse_mod, is_prime
from sage.quadratic_forms.binary_qf import BinaryQF


def mod_floor(a: int, b: int) -> int:
    """Compute a mod b with floor division semantics: result r satisfies 0 <= r < |b|."""
    r = a % b
    if (r < 0 < b) or (r > 0 > b):
        r += b
    return r


def prime_form(D: int, p: int) -> BinaryQF:
    """
    Construct a binary quadratic form [p, b, c] of discriminant D representing prime p.
    Mimics PARI/GP's primeform(D, p).
    """
    if D >= 0 or D % 4 not in [0, 1]:
        raise ValueError("D must be a negative discriminant congruent to 0 or 1 mod 4")
    if not is_prime(p):
        raise ValueError("p must be a prime integer")

    modulus = 4 * p
    for b in range(2 * p):
        if (b * b - D) % modulus == 0:
            c = (b * b - D) // (4 * p)
            return BinaryQF([p, b, c])  # Automatically reduced

    raise ValueError(f"No valid b found such that b^2 ≡ D mod 4p for D={D}, p={p}")


def construct_binary_qf(a: int, b: int, delta: int) -> BinaryQF:
    """
    Construct BinaryQF from a, b, delta where delta ≡ 1 mod 4 and delta < 0.
    """
    assert mod_floor(delta, 4) == 1, "delta must be ≡ 1 mod 4"
    assert delta < 0, "delta must be negative"

    c = (b ** 2 - delta) // (4 * a)
    return BinaryQF([a, b, c])


def construct_binary_qf_from_principle(delta: int) -> BinaryQF:
    """
    Return the principal form for a discriminant delta.
    """
    return construct_binary_qf(a=1, b=1, delta=delta)


def binary_qf_pow(f: BinaryQF, n: int) -> BinaryQF:
    """
    Raise binary quadratic form f to the power n via repeated composition.
    Assumes f is reduced and has negative discriminant.
    """
    if n == 0:
        raise ValueError("n must be a positive integer")

    result = f
    for _ in range(n - 1):
        result = (result * f).reduced_form()
    return result


def binary_qf_inverse(f: BinaryQF) -> BinaryQF:
    """
    Raise binary quadratic form f to the power n via repeated composition.
    Assumes f is reduced and has negative discriminant.
    """
    return BinaryQF([f[0], -f[1], f[2]]).reduced_form()


def phi_q_inverse(f: BinaryQF, conductor: int) -> BinaryQF:
    """
    Compute the preimage of a form f under the morphism induced by conductor embedding.
    """
    a, b = f[0], f[1]
    b_new = mod_floor(b * conductor, 2 * a)
    delta = f.discriminant() * conductor ** 2

    return construct_binary_qf(a, b_new, delta)


def expo_f(p: int, delta: int, k: int) -> BinaryQF:
    """
    Construct the form f = [p^2, pk_inv, c] with discriminant delta,
    where k_inv is the inverse of k mod p.
    If k == 0, return principal form.
    """
    if k == 0:
        return construct_binary_qf_from_principle(delta)

    k_inv = inverse_mod(k, p)
    if mod_floor(k_inv, 2) == 0:
        k_inv -= p

    a = p * p
    b = k_inv * p
    return construct_binary_qf(a, b, delta)


def discrete_log_f(p: int, delta: int, c: BinaryQF) -> int:
    """
    Recover exponent x from form c = f^x, where f is the generator constructed from (p, delta).
    Assumes form is of the shape resulting from expo_f().
    """
    principal_qf = construct_binary_qf_from_principle(delta)
    if c == principal_qf:
        return 0

    b = c[1]
    Lk = b // p
    return inverse_mod(Lk, p)
