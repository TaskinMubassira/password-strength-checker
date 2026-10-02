from password_checker.breach import sha1_hex, times_pwned


class FakeResponse:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


class FakeSession:
    """Records the requested URL and returns a canned range response."""

    def __init__(self, text):
        self.text = text
        self.url = None

    def get(self, url, headers=None, timeout=None):
        self.url = url
        return FakeResponse(self.text)


def test_only_the_hash_prefix_is_sent():
    secret = "Tiger-Lantern-42"
    session = FakeSession("")
    times_pwned(secret, session=session)
    assert session.url.endswith("/" + sha1_hex(secret)[:5])
    assert secret.lower() not in session.url.lower()


def test_counts_a_matching_suffix():
    digest = sha1_hex("password")
    session = FakeSession(f"0000000000000000000000000000000000A:3\r\n{digest[5:]}:9545824\r\n")
    assert times_pwned("password", session=session) == 9545824


def test_not_found_returns_zero():
    assert times_pwned("unlikely", session=FakeSession("ABCDEF:1\r\n")) == 0
