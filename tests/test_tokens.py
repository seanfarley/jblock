

import pytest

from jblock import token

TOKENS = {
	"https://snowplow.trx.gitlab.net/com.snowplowanalytics.snowplow/tp2":
	['https', 'snowplow', 'trx', 'gitlab', 'net', 'com', 'snowplowanalytics', 'snowplow', 'tp2'],
	"https://secure.gravatar.com/avatar/8a29de2d7fbed6e86662f066a4f1ca71?s=48&d=identicon":
	['https', 'secure', 'gravatar', 'com', 'avatar', '8a29de2d7fbed6e86662f066a4f1ca71', 's', '48', 'd', 'identicon'],
	"https://assets.gitlab-static.net/assets/webpack/pages.projects.commit.show.9694cec7.ch":
	['https', 'assets', 'gitlab', 'static', 'net', 'assets', 'webpack', 'pages', 'projects', 'commit', 'show', '9694cec7', 'ch'],
	"https://assets.gitlab-static.net/assets/webpack/runtime.e0be7892.bundle.js":
	['https', 'assets', 'gitlab', 'static', 'net', 'assets', 'webpack', 'runtime', 'e0be7892', 'bundle', 'js'],
	"https://start.duckduckgo.com/":
	['https', 'start', 'duckduckgo', 'com', ''],
	"https://github.com/qutebrowser/qutebrowser":
	['https', 'github', 'com', 'qutebrowser', 'qutebrowser'],
}


@pytest.mark.parametrize(('url', 'tokens'), TOKENS.items())
def test_token_basic(url, tokens):
	assert token.TokenConverter.url_to_token(url) == tokens


## Benchmarks

def test_token_str_bench(benchmark):
	benchmark(lambda: list(map(token.TokenConverter.url_to_token, TOKENS.keys())))


@pytest.mark.skip()
def test_token_int_bench(benchmark):
	"""Looks like int hashing is slower than re split."""
	benchmark(lambda: list(map(token.TokenConverter.url_to_token_int, TOKENS.keys())))
