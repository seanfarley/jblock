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

import attr

from jblock import parser, token, domain_tools

class JBlockBuckets():
	"""Handle logic for maintaining and updating filter buckets."""

	def __init__(self, rules: typing.List[str], supported_options=parser.JBlockRule.OPTIONS):
		# TODO use more than one bucket
		self.supported_options = supported_options
		self.bucket = JBlockBucket(rules, supported_options=supported_options)


	def should_block(self, url, options=None) -> bool:
		return self.bucket.should_block(url, options)

	def __len__(self):
		return len(self.bucket)


@attr.attributes(slots=True)
class JBlockBucket():
	"""Class representing a single bucket."""

	rules = attr.attr(type=typing.MutableSequence[str])
	supported_options = attr.attr(default=parser.JBlockRule.OPTIONS)
	skip_unsupported_rules = attr.attr(default=True)
	blacklist = attr.attr(init=False)
	blacklist_re = attr.attr(init=False)
	whitelist = attr.attr(init=False)
	whitelist_re = attr.attr(init=False)
	blacklist_with_options = attr.attr(init=False)
	whitelist_with_options = attr.attr(init=False)
	blacklist_require_domain = attr.attr(init=False)
	whitelist_require_domain = attr.attr(init=False)


	def __attrs_post_init__(self):
		_params = dict((opt, True) for opt in self.supported_options)
		self.rules = [
			r for r in (
				r if isinstance(r, parser.JBlockRule) else parser.JBlockRule(r)
				for r in self.rules
			)
			if (r.regex or r.options) and r.matching_supported(_params)
		]

		# "advanced" rules are rules with options,
		# "basic" rules are rules without options
		advanced_rules, basic_rules = domain_tools.split_iter(self.rules, lambda r: r.options)

		# Rules with domain option are handled separately:
		# if user passes a domain we can discard all rules which
		# require another domain. So we build an index:
		# {domain: [rules_which_require_it]}, and only check
		# rules which require our domain. If a rule doesn't require any
		# domain.
		# TODO: what about ~rules? Should we match them earlier?
		domain_required_rules, non_domain_rules = domain_tools.split_iter(
			advanced_rules,
			lambda r: (
				'domain' in r.options
				and any(r.options["domain"].values())
			)
		)

		# split rules into blacklists and whitelists
		self.blacklist, self.whitelist = domain_tools.split_bw(basic_rules)
		_combined = functools.partial(domain_tools.combined_regex)
		self.blacklist_re = _combined([r.regex for r in self.blacklist])
		self.whitelist_re = _combined([r.regex for r in self.whitelist])

		self.blacklist_with_options, self.whitelist_with_options = \
			domain_tools.split_bw(non_domain_rules)
		self.blacklist_require_domain, self.whitelist_require_domain = \
			domain_tools.split_bw_domain(domain_required_rules)

	def should_block(self, url, options=None) -> bool:
		# TODO: group rules with similar options and match them in bigger steps
		options = options or {}
		if self._is_whitelisted(url, options):
			return False
		if self._is_blacklisted(url, options):
			return True
		return False

	def _is_whitelisted(self, url, options):
		return self._matches(
			url, options,
			self.whitelist_re,
			self.whitelist_require_domain,
			self.whitelist_with_options
		)

	def _is_blacklisted(self, url, options):
		return self._matches(
			url, options,
			self.blacklist_re,
			self.blacklist_require_domain,
			self.blacklist_with_options
		)

	def _matches(self, url, options,
				 general_re, domain_required_rules, rules_with_options):
		"""
		Return if ``url``/``options`` are matched by rules defined by
		``general_re``, ``domain_required_rules`` and ``rules_with_options``.

		``general_re`` is a compiled regex for rules without options.

		``domain_required_rules`` is a {domain: [rules_which_require_it]}
		mapping.

		 ``rules_with_options`` is a list of AdblockRule instances that
		don't require any domain, but have other options.
		"""
		if general_re and general_re.search(url):
			return True

		rules = []
		if 'domain' in options and domain_required_rules:
			src_domain = options['domain']
			for d in domain_tools.domain_variants(src_domain):
				if d in domain_required_rules:
					rules.extend(domain_required_rules[d])

		rules.extend(rules_with_options)

		if self.skip_unsupported_rules:
			rules = [rule for rule in rules if rule.matching_supported(options)]

		return any(rule.match_url(url, options) for rule in rules)

	def __len__(self):
		return len(self.rules)
