# Copyright (C) 2019  Jay Kamat
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import re
import typing

Token = str


class TokenConverter():
	"""Static class for housing token conversion methods"""

	VALID_TOKEN_CHARS = frozenset('0123456789%abcdefghijklmnopqrstuvwxyz')
	VALID_TOKEN_CHARS_INT = frozenset(map(ord, VALID_TOKEN_CHARS))
	VALID_TOKEN_CHAR_RE = re.compile(r'[^0-9a-z%]+')

	REGEX_TOKEN_RE = re.compile(r'[%0-9A-Za-z]{2,}')
	# If we match this from start of the string, all hope is lost for this token and the rest
	REGEX_TOKEN_ABORT = re.compile(r'[([]')
	# TODO find out if this blocks the case where we do *pattern
	REGEX_BAD_PREFIX = re.compile(r'(^|[^\\]\.|[*?{}\\])$')
	REGEX_BAD_SUFFIX = re.compile(r'^([^\]\.|\[dw]|[([{}?*]|$)')
	# These tokens won't interfere with proper matching, they just slow us down.
	# This needs tuning
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
			# prefix is from the start of the string to the start of the match
			prefix = s[0:match.start(0)]
			suffix = s[match.end(0) + 1:]
			match = match.group(0).lower()

			# If we have any of these characters leading to our match, we cannot reliably get a substring (this token
			# could be in an optional match or char class)
			if TokenConverter.REGEX_TOKEN_ABORT.search(prefix):
				return tokens

			if (TokenConverter.REGEX_BAD_PREFIX.search(prefix) or
				TokenConverter.REGEX_BAD_SUFFIX(suffix)):
				# This token is unsuitable.
				continue

			tokens.append(match)
