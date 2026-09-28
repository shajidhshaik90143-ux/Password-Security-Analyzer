import secrets
import string

WORDS = [
    "amber","anchor","apple","apricot","arrow","atlas","autumn","beacon",
    "birch","blue","breeze","bridge","cactus","canyon","cedar","circle",
    "cloud","comet","copper","coral","crystal","delta","desert","ember",
    "falcon","forest","galaxy","garden","glacier","harbor","horizon","island",
    "jasmine","jungle","lantern","lemon","lunar","maple","meadow","meteor",
    "mountain","nebula","ocean","olive","orange","orchid","otter","panda",
    "pebble","planet","prairie","quartz","raven","river","rocket","saffron",
    "sierra","silver","solar","sparrow","spring","summit","sunset","tiger",
    "valley","violet","walnut","willow","winter","zephyr"
]

AMBIGUOUS = set("O0oIl1|`'\"")

def _filter(chars, avoid_ambiguous):
    if avoid_ambiguous:
        chars = "".join(c for c in chars if c not in AMBIGUOUS)
    return chars

def generate_password(length=20, use_upper=True, use_lower=True, use_digits=True,
                      use_symbols=True, avoid_ambiguous=True):
    if length < 8:
        raise ValueError("Use at least 8 characters.")
    pools = []
    if use_lower: pools.append(_filter(string.ascii_lowercase, avoid_ambiguous))
    if use_upper: pools.append(_filter(string.ascii_uppercase, avoid_ambiguous))
    if use_digits: pools.append(_filter(string.digits, avoid_ambiguous))
    if use_symbols: pools.append(_filter(string.punctuation, avoid_ambiguous))
    if not pools:
        raise ValueError("Select at least one character category.")
    if length < len(pools):
        raise ValueError("Password length is too short for all selected categories.")

    result = [secrets.choice(pool) for pool in pools]
    all_chars = "".join(pools)
    result.extend(secrets.choice(all_chars) for _ in range(length - len(result)))
    secrets.SystemRandom().shuffle(result)
    return "".join(result)

def generate_passphrase(words=5, separator="-"):
    if not 3 <= words <= 20:
        raise ValueError("Words must be between 3 and 20.")
    return separator.join(secrets.choice(WORDS) for _ in range(words))
