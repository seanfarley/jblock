
import re
import typing

Token = str


class TokenConverter():
	"""Static class for housing token conversion methods"""

	VALID_TOKEN_CHARS = frozenset('0123456789%abcdefghijklmnopqrstuvwxyz')
	VALID_TOKEN_CHARS_INT = frozenset(map(ord, VALID_TOKEN_CHARS))
	VALID_TOKEN_CHAR_RE = re.compile(r'[^0-9a-z%]+')

	REGEX_TOKEN_RE = re.compile(r'[%0-9A-Za-z]{2,}')
	REGEX_TOKEN_ABORT = re.compile(r'[([]')
	# These tokens won't interfere, they just slow us down.
	REGEX_BAD_PREFIX = re.compile(r'(^|[^\\]\.|[*?{}\\])$')
	REGEX_BAD_SUFFIX = re.compile(r'^([^\]\.|\[dw]|[([{}?*]|$)')
	BAD_TOKENS = frozenset(['com', 'http', 'https', 'icon', 'images', 'img',
						   'js', 'net', 'news', 'www'])

	@staticmethod
	def url_to_tokens(s: str) -> typing.MutableSequence[Token]:
		"""Convert a URL to a list of tokens.

		This is in the critical path, so we need to do as little python as possible ;)
		"""
		return TokenConverter.VALID_TOKEN_CHAR_RE.split(s.lower())

	@staticmethod
	def url_to_tokens_int(s: str) -> typing.MutableSet[int]:
		"""Alternative int token generation.

		Seems to be 2x slower than the re based solution.

		Based on this absolute mess:
		https://github.com/gorhill/uBlock/blob/261ef8c510fd91ead57948d1f7793a7a5e2a25fd/src/js/utils.js#L81
		"""
		tally, tokens, arr = 0, set(), bytearray(s, 'ascii')
		for char in arr:
			if char in TokenConverter.VALID_TOKEN_CHARS_INT:
				tally += char
			else:
				tokens.add(tally)
				tally = 0
		return tokens


	@staticmethod
	def regex_to_tokens(s: str) -> typing.MutableSequence[Token]:
		"""Convert a regex to tokens, if possible.

		https://github.com/gorhill/uBlock/blob/4f3aed6fe6347572c38ec9a293f933387b81e5de/src/js/static-net-filtering.js#L1921
		"""
		tokens = []
		for match in TokenConverter.REGEX_TOKEN_RE.finditer(s):
			match = match.group(0)
