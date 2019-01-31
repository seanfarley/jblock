
import re
import typing

Token = str


class TokenConverter():
	"""Static class for housing token conversion methods"""

	VALID_TOKEN_CHARS = frozenset('0123456789%abcdefghijklmnopqrstuvwxyz')
	VALID_TOKEN_CHARS_INT = frozenset(map(ord, VALID_TOKEN_CHARS))
	VALID_TOKEN_RE = re.compile('[^0-9%a-z]+')

	@staticmethod
	def url_to_token(s: str) -> typing.MutableSequence[Token]:
		return TokenConverter.VALID_TOKEN_RE.split(s.lower())

	@staticmethod
	def url_to_token_int(s: str) -> typing.MutableSet[Token]:
		"""Alternative int token generation"""
		tally, tokens, s = 0, set(), bytearray(s, 'ascii')
		for char in s:
			if char in TokenConverter.VALID_TOKEN_CHARS_INT:
				tally += char
			else:
				tokens.add(tally)
				tally = 0
		return tokens
