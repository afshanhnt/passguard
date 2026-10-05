"""Cryptographically secure password and passphrase generation."""
import secrets
import string

# Small demo wordlist. For real use, swap in the EFF large wordlist (7776 words).
WORDS = (
    "anchor apple badge beacon birch bridge candle canyon cedar cliff cloud comet "
    "copper coral crystal dawn delta ember falcon fern flint forest galaxy garden "
    "glacier harbor hazel horizon island jungle lantern lemon maple meadow mirror "
    "mountain nebula ocean olive orbit pebble pepper pine planet quartz raven river "
    "saddle shadow silver spark spruce summit thunder timber tulip valley velvet "
    "violet willow winter zephyr banana beach month school food country colors "
    "iron metal love hate animal"
).split()


def generate_password(length: int = 16, symbols: bool = True) -> str:
    if length < 8:
        raise ValueError("Length must be at least 8.")
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?")
    alphabet = "".join(pools)
    # Guarantee one character from each pool, then fill the rest randomly.
    chars = [secrets.choice(p) for p in pools]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_passphrase(words: int = 5, separator: str = "-") -> str:
    if words < 3:
        raise ValueError("Use at least 3 words.")
    return separator.join(secrets.choice(WORDS) for _ in range(words))
