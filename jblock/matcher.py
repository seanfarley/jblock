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

from jblock.tools import JBlockParseError, AnchorTypes


class Matcher:
	__slots__ = []  #  type: typing.List[str]

	def hit(self, url: str) -> bool:
		"""Whether this rule hits on this URL."""
		raise NotImplementedError

	def dummy_matcher(self) -> bool:
		"""Return true if this matcher is a dummy matcher (ideally should be removed)."""
		return False

def gen_matcher(rule: str, anchors: typing.Set[AnchorTypes]) -> typing.Optional[Matcher]:
	"""Generate and return an appropriate matcher for this rule"""
	rule = rule.strip()
	if not rule or rule == "*":
		return AlwaysTrueMatcher()

	# Check if rule is regexp
	if rule.startswith('/') and rule.endswith('/'):
		if len(rule) > 1: return RegexMatcher(rule[1:-1])
		else: raise JBlockParseError('Error parsing rule "{}"'.format(rule))

	# TODO handle plain hostname matching

	return GenericMatcher(rule, anchors)

class AlwaysTrueMatcher(Matcher):
	"""Matcher that always returns True"""

	def hit(self, _url: str) -> bool:
		return True

	def dummy_matcher(self) -> bool:
		return True

class GenericMatcher(Matcher):
	"""Matcher for generic rules (ie: not optimized at all)."""

	__slots__ = ['rule']  #  type: typing.List[str]

	def __init__(self, rule: str, anchors: typing.Set[AnchorTypes]) -> None:
		self.rule = GenericMatcher._rule_to_regex(rule, anchors)  # type: typing.Optional[Pattern]
		super().__init__()

	def hit(self, url: str) -> bool:
		if self.rule is not None:
			return bool(self.rule.search(url))
		return True

	@staticmethod
	def _rule_to_regex(rule: typing.Optional[str], anchors: typing.Set[AnchorTypes]) -> typing.Optional[Pattern]:
		"""
		Convert AdBlock rule to a regular expression.

		https://github.com/gorhill/uBlock/blob/4f3aed6fe6347572c38ec9a293f933387b81e5de/src/js/static-net-filtering.js#L139
		"""
		if not rule:
			return None

		# Replace special characters that interfere with regexp
		rule = re.sub(r"([.+?${}()|[\]\\])", r"\\\1", rule)

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
		rule = re.sub(r'^\*|\*$', '', rule)

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

		return re.compile(rule)

class RegexMatcher(Matcher):

	__slots__ = ['rule']  #  type: typing.List[str]

	def __init__(self, rule: str) -> None:
		self.rule = re.compile(rule)  # type: Pattern
		super().__init__()

	def hit(self, url: str) -> bool:
		if self.rule is not None:
			return bool(self.rule.search(url))
		return True
