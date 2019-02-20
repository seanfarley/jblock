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

import re
import typing
import functools
import itertools
import collections
import operator
import pprint

import attr

from jblock import parser, token, matcher

@attr.attributes(slots=True)
class JBlockBucket():
	"""Class representing a single bucket."""

	rules = attr.attr(type=typing.MutableSequence[parser.JBlockRule])
	supported_options = attr.attr(default=parser.JBlockRule.OPTIONS)

	def __attrs_post_init__(self):
		_params = dict((opt, True) for opt in self.supported_options)
		self.rules = [
			r for r in (
				r if isinstance(r, parser.JBlockRule) else parser.JBlockRule(r)
				for r in self.rules
			)
			if (not r.matcher.dummy_matcher() or r.options) and r.matching_supported(_params)
		]

	def hit(self, url, options=None):
		"Return true if any of the rules in this bucket are matched by the url."
		return any(rule.match_url(url, options) for rule in self.rules)

	def __len__(self):
		return len(self.rules)


@attr.attributes(slots=True)
class JBlockBucketGroup():
	"""Class representing a group of buckets.

ie: an accept and a fail bucket, all with one tag.

	"""
	bucket_token = attr.attr(type=token.Token)
	blacklist = attr.attr(default=attr.Factory(JBlockBucket))
	whitelist = attr.attr(default=attr.Factory(JBlockBucket))

	def __len__(self):
		return len(self.blacklist) + len(self.whitelist)


class JBlockBuckets():
	"""Handle logic for maintaining and updating filter buckets."""

	def __init__(self, rules: typing.List[str], supported_options=parser.JBlockRule.OPTIONS):
		# TODO use more than one bucket
		self.rules = rules
		self.unsupported_rules = []  # type: typing.List[token.Token]
		self.supported_options = supported_options
		self.bucket_groups = {}  # type: typing.Dict[token.Token, JBlockBucketGroup]
		self._gen_buckets()

	def _gen_buckets(self):
		bucket_agg = collections.defaultdict(list)
		fallback_rules = []
		s_opt_dict = dict(map(lambda v: (v, True), self.supported_options))
		for r in self.rules:
			if isinstance(r, parser.JBlockRule):
				rule = r
			else:
				rule = parser.JBlockRule(r)
			if not rule.matching_supported(s_opt_dict):
				self.unsupported_rules.append(r)
				continue
			t = self._pick_token(rule)
			if t is None:
				fallback_rules.append(rule)
			else:
				bucket_agg[t].append(rule)
		for k, v in bucket_agg.items():
			self.bucket_groups[k] = self._rule_list_to_bucket_group(k, v)
		self.fallback_bucket_group = self._rule_list_to_bucket_group("FALLBACK", fallback_rules)
		# import pprint
		# pprint.pprint(bucket_agg)
		# pprint.pprint(sorted(list(map(len, bucket_agg.values()))))
		# pprint.pprint(fallback_rules)
		# for k, v in bucket_agg.items():
		# 	if len(v) > 50:
		# 		print(k)
		# 		print(v)

	def _rule_list_to_bucket_group(
			self, bucket_token: token.Token,
			rule_list: typing.List[parser.JBlockRule]) -> JBlockBucketGroup:
		"""Generate a bucket group from a list of block rules and a token"""
		blacklist = []
		whitelist = []
		for rule in rule_list:
			if rule.is_exception:
				whitelist.append(rule)
			else:
				blacklist.append(rule)
		return JBlockBucketGroup(
			bucket_token, JBlockBucket(blacklist), JBlockBucket(whitelist))


	def _pick_token(self, rule):
		if rule.tokens:
			return rule.tokens[0]
		return None


	def should_block(self, url: str, options=None) -> bool:
		"""Decide if we should block a URL with OPTIONS.
		Probabilities are: No Hit, Hit on Block, Hit on Block with Override

		So:
		1. Check all blacklist filters
		2. Check all whitelist filters (if that hit)"""
		tokens, block = token.TokenConverter.url_to_tokens(url), False
		for t in tokens:
			group = self.bucket_groups.get(t, None)
			if group and group.blacklist.hit(url, options):
				block = True
				break

		if not block:
			block = self.fallback_bucket_group.blacklist.hit(url, options)

		if not block:
			return False

		for t in tokens:
			group = self.bucket_groups.get(t, None)
			if group and group.whitelist.hit(url, options):
				block = False
				break
		if block:
			block = not self.fallback_bucket_group.whitelist.hit(url, options)

		return block

	def __len__(self):
		return sum(map(len, self.bucket_groups.values())) + len(self.fallback_bucket_group)

	def summary_str(self):
		"""Get a summary string, helping diagnose bucketing problems."""
		def _bucket_group_to_summary(group: JBlockBucketGroup):
			return (
				group.bucket_token + ": " +
				str(len(group.blacklist)) +
				", " + str(len(group.whitelist)))
		summary = ["TOTAL: " + str(len(self))]
		summary += [_bucket_group_to_summary(self.fallback_bucket_group)]
		groups = sorted(self.bucket_groups.values(), key=len, reverse=True)[:10]
		group_str = map(_bucket_group_to_summary, groups)
		summary.extend(group_str)
		return "\n".join(summary)
