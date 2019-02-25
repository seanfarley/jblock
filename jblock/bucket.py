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

from jblock import parser, token, matcher, tools

class JBlockBucket():
	"""Class representing a single bucket."""

	__slots__ = ['supported_options', 'rules',
				 'domain_hitlist', 'domain_exceptionlist', 'length']  # type: typing.List[str]

	def __init__(self, rules: typing.MutableSequence[parser.JBlockRule],
				 supported_options: typing.AbstractSet[str] = parser.JBlockRule.OPTIONS):
		self.supported_options = supported_options
		self.domain_hitlist = collections.defaultdict(set)  # type: typing.Dict[str, typing.Set[parser.JBlockRule]]
		self.domain_exceptionlist = collections.defaultdict(set)  # type: typing.Dict[str, typing.Set[parser.JBlockRule]]
		# Rules that always apply to this bucket
		self.rules = set()  # type: typing.Set[parser.JBlockRule]
		self.length = 0

		_params = dict((opt, True) for opt in self.supported_options)
		for r in rules:
			if (r.matcher is None or
				(r.matcher.dummy_matcher() and not r.options) or
				not r.matching_supported(_params)):
				continue

			self.length += 1

			if r.options.get('domain'):
				all_exceptions = True
				for domain, allow in r.options['domain'].items():
					if allow:
						all_exceptions = False
						self.domain_hitlist[domain].add(r)
					else:
						self.domain_exceptionlist[domain].add(r)
				if all_exceptions:
					# If we are nothing but exceptions, we need to add ourselves to the generic rules as well (and
					# possibly get negated in the exceptionlist)
					self.rules.add(r)
			else:
				self.rules.add(r)

	def hit(self, url, domain_variants, options=None):
		"Return true if any of the rules in this bucket are matched by the url."
		rules_to_check = set(self.rules)
		rules_in_flight = set()
		exceptions_in_flight = set()
		# Add all exception rules, then add any hit rules, then remove all exception rules that hit.
		# We also have to have more specific rules override less specific rules.

		# TODO try to avoid set copies here
		for variant in domain_variants:
			# If a rule already made it in, don't blacklist it
			exceptions_in_flight.update(self.domain_exceptionlist.get(variant, set()) - rules_in_flight)
			# if a rule already made it in, don't whitelist it
			rules_in_flight.update(self.domain_hitlist.get(variant, set()) - exceptions_in_flight)

		rules_to_check.difference_update(exceptions_in_flight)
		rules_to_check.update(rules_in_flight)
		# for variant in domain_variants:
		# 	rules_to_check.difference_update(self.domain_exceptionlist.get(variant, []))

		return any(rule.match_url(url, options, ignore_domain=True) for rule in rules_to_check)

	def __len__(self):
		return self.length


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

	def __init__(self,
				 rules: typing.List[str],
				 supported_options=parser.JBlockRule.OPTIONS,
				 token_frequency: typing.Dict[token.Token, int] = {}):
		self.rules = rules
		self.unsupported_rules = []  # type: typing.List[token.Token]
		self.supported_options = supported_options
		self.bucket_groups = {}  # type: typing.Dict[token.Token, JBlockBucketGroup]
		if token_frequency:
			self.token_frequency = token_frequency
		else:
			self.token_frequency = collections.defaultdict(int)  # type: typing.Dict[token.Token, int]
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
		if self.token_frequency:
			return min(
				rule.tokens, default=None,
				key=lambda k: self.token_frequency.get(k, 0))
		else:
			if rule.tokens:
				return rule.tokens[0]
			return None

	def get_token_frequency(self):
		"""Get a token frequency object, so we can speed up accesses next time we create an adblocker."""
		return self.token_frequency

	def regen_buckets(self):
		"""Regenerate buckets to take advantage of (new) token profiling."""
		self._gen_buckets()

	def should_block(self, url: str, options=None) -> bool:
		"""Decide if we should block a URL with OPTIONS.
		Probabilities are: No Hit, Hit on Block, Hit on Block with Override

		So:
		1. Check all blacklist filters
		2. Check all whitelist filters (if that hit)"""
		tokens, block = token.TokenConverter.url_to_tokens(url), False
		if options is not None and 'domain' in options:
			domain_variants = list(tools.domain_variants(options['domain']))
		else:
			domain_variants = []

		# Update token frequency map (so we can get faster later)
		for t in tokens: self.token_frequency[t] += 1

		for t in tokens:
			group = self.bucket_groups.get(t, None)
			if group and group.blacklist.hit(url, domain_variants, options):
				block = True
				break

		if not block:
			block = self.fallback_bucket_group.blacklist.hit(url, domain_variants, options)

		if not block:
			return False

		for t in tokens:
			group = self.bucket_groups.get(t, None)
			if group and group.whitelist.hit(url, domain_variants, options):
				block = False
				break
		if block:
			block = not self.fallback_bucket_group.whitelist.hit(url, domain_variants, options)

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
