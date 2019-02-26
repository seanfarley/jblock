# Copyright (C) 2019  Jay Kamat <jaygkamat@gmail.com>
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

"""Classes that assist in determining if a url matches a particular rule."""

import typing
from typing import Pattern
import re
import operator
import functools

from jblock.tools import JBlockParseError, AnchorTypes

RULE_IS_GENERIC = re.compile(r'[\^\*]')
SCHEME_STR = "://"
POST_HOSTNAME_CHARS = re.compile(r'[\/?#]')
HOSTNAME_END_ANCHORS = frozenset([AnchorTypes.END, AnchorTypes.HOSTNAME])


class Matcher:
	__slots__ = []  #  type: typing.List[str]

	def hit(self, url: str) -> bool:
		"""Whether this rule hits on this URL.

		This function needs to be implemented as fast as possible."""
		raise NotImplementedError

	def dummy_matcher(self) -> bool:
		"""Return true if this matcher is a dummy matcher (ideally should be removed)."""
		return False

def gen_matcher(rule: str, anchors: typing.Container[AnchorTypes]) -> Matcher:
	"""Generate and return an appropriate matcher for this rule"""
	rule = rule.strip()
	if not rule or rule == "*":
		return AlwaysTrueMatcher()

	# Check if rule is regexp
	if rule.startswith('/') and rule.endswith('/'):
		if len(rule) > 1: return RegexMatcher(rule[1:-1])
		else: raise JBlockParseError('Error parsing rule "{}"'.format(rule))

	# TODO handle plain hostname matching

	if all(map(functools.partial(operator.contains, anchors), HOSTNAME_END_ANCHORS)):
		if RULE_IS_GENERIC.search(rule):
			return GenericMatcher(rule, anchors)
		# No special characters, we can get away with plain matching
		# return PlainHnEndAnchoredMatcher(rule)

	return GenericMatcher(rule, anchors)

class AlwaysTrueMatcher(Matcher):
	"""Matcher that always returns True"""

	def hit(self, _url: str) -> bool:
		return True

	def dummy_matcher(self) -> bool:
		return True

class GenericMatcher(Matcher):
	"""Matcher for generic rules (ie: not optimized at all)."""

	SPECIAL_CHARACTER_RE = re.compile(r"([.+?${}()|[\]\\])")
	FRONT_BACK_STAR = re.compile(r'^\*|\*$')

	__slots__ = ['rule']  #  type: typing.List[str]

	def __init__(self, rule: str, anchors: typing.Container[AnchorTypes]) -> None:
		self.rule = GenericMatcher._rule_to_regex(rule, anchors)  # type: typing.Union[Pattern, str]
		super().__init__()

	def hit(self, url: str) -> bool:
		try:
			return bool(self.rule.search(url))  # type: ignore
		except AttributeError:
			if isinstance(self.rule, str):
				self.rule = re.compile(self.rule)
				return bool(self.rule.search(url))
			raise JBlockParseError('Internal error with rule: "{}"'.format(self.rule))

	@staticmethod
	def _rule_to_regex(rule: str, anchors: typing.Container[AnchorTypes]) -> str:
		"""
		Convert AdBlock rule to a regular expression.

		https://github.com/gorhill/uBlock/blob/4f3aed6fe6347572c38ec9a293f933387b81e5de/src/js/static-net-filtering.js#L139
		"""

		# Replace special characters that interfere with regexp
		rule = GenericMatcher.SPECIAL_CHARACTER_RE.sub(r"\\\1", rule)

		# XXX: the resulting regex must use non-capturing groups (?:
		# for performance reasons; also, there is a limit on number
		# of capturing groups, no using them would prevent building
		# a single regex out of several rules.

		# Separator character ^ matches anything but a letter, a digit, or
		# one of the following: _ - . %. The end of the address is also
		# accepted as separator.
		rule = rule.replace("^", r'(?:[^%.0-9a-z_-]|$)')

		# TODO add this when we no longer concatenate all the rules together
		# Remove * at front or back of rule
		rule = GenericMatcher.FRONT_BACK_STAR.sub('', rule)

		# * symbol
		rule = rule.replace("*", '[^ ]*?')

		if AnchorTypes.HOSTNAME in anchors:
			# Prepend a scheme regex
			prepend = r'^[a-z-]+://(?:[^/?#]+)?' if rule.startswith(r'\.') else r'^[a-z-]+://(?:[^/?#]+\.)?'
			rule = prepend + rule
		elif AnchorTypes.START in anchors:
			rule = '^' + rule

		if AnchorTypes.END in anchors:
			rule = rule + '$'

		return rule

class RegexMatcher(Matcher):

	__slots__ = ['rule']  #  type: typing.List[str]

	def __init__(self, rule: str) -> None:
		self.rule = re.compile(rule)  # type: Pattern
		super().__init__()

	def hit(self, url: str) -> bool:
		return bool(self.rule.search(url))

class PlainHnEndAnchoredMatcher(Matcher):

	__slots__ = ['rule']  #  type: typing.List[str]

	def __init__(self, rule: str) -> None:
		self.rule = rule
		super().__init__()

	def hit(self, url: str) -> bool:
		if not url.endswith(self.rule):
			return False
		match_index = len(url) - len(self.rule)

		scheme_index = url.find(SCHEME_STR)
		if scheme_index == -1:
			return False
		scheme_index += len(SCHEME_STR)

		if match_index <= scheme_index:
			return True

		if (url[match_index - 1] != '.' or
			POST_HOSTNAME_CHARS.search(url[scheme_index:match_index])):
			return False

		return True

class PlainHnAnchoredMatcher(Matcher):

	__slots__ = ['rule']  #  type: typing.List[str]

	def __init__(self, rule: str) -> None:
		self.rule = rule
		super().__init__()

	def hit(self, url: str) -> bool:
		scheme_index = url.find(SCHEME_STR)
		if scheme_index == -1:
			return False

		scheme_index += len(SCHEME_STR)
		match_index = url.find(self.rule, scheme_index)
		if match_index < 1:
			return False

		if match_index <= scheme_index:
			return True

		if (url[match_index - 1] != '.' or
			POST_HOSTNAME_CHARS.search(url[scheme_index:match_index])):
			return False

		return True
