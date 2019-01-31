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
#

## Some parts of this file were adapted from scrapinghub/adblockparser.
# Their copyright is reproduced below.
# Copyright (c) 2014 ScrapingHub Inc.

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


import re
import attr
import typing
import itertools
import functools
import collections

class JBlockParseError(ValueError):
    pass


@attr.attributes(slots=True)
class JBlockRule():
	"""An individual rule which a URL can be matched against."""
	OPTIONS = frozenset({
		"script",
		"image",
		"stylesheet",
		"object",
		"xmlhttprequest",
		"object-subrequest",
		"subdocument",
		"document",
		"elemhide",
		"other",
		"background",
		"xbl",
		"ping",
		"dtd",
		"media",
		"third-party",
		"match-case",
		"collapse",
		"donottrack",
		"websocket",
		# domain is a special case!
		"domain",})

	OPTIONS_SPLIT_RE = re.compile(',(?=~?(?:%s))' % ('|'.join(OPTIONS)))

	raw_text = attr.attr(type=str)
	rule_text = attr.attr(init=False, type=str)
	regex_re = attr.attr(init=False, type=typing.Optional[typing.Pattern], default=None)

	is_comment = attr.attr(init=False, type=bool)

	@is_comment.default
	def c_init(self):
		return not self.raw_text or self.raw_text.startswith(('!', '[Adblock'))

	is_html_rule = attr.attr(init=False, type=bool)
	is_exception = attr.attr(init=False, type=bool)
	raw_options = attr.attr(init=False, type=typing.List)
	options = attr.attr(init=False, type=typing.Dict)
	regex = attr.attr(init=False, type=str)
	_options_keys = attr.attr(init=False)


	def __attrs_post_init__(self) -> None:
		self.rule_text = self.raw_text.strip()
		if self.is_comment:
			self.is_html_rule = self.is_exception = False
		else:
			# should we use single pound here too?
			self.is_html_rule = '##' in self.rule_text or '#@#' in self.rule_text
			self.is_exception = self.rule_text.startswith('@@')
			if self.is_exception:
				self.rule_text = self.rule_text[2:]

		if not self.is_comment and '$' in self.rule_text:
			self.rule_text, options_text = self.rule_text.split('$', 1)
			self.raw_options = self._split_options(options_text)
			self.options = dict(self._parse_option(opt) for opt in self.raw_options)
		else:
			self.raw_options = []
			self.options = {}
		self._options_keys = frozenset(self.options.keys()) - set(['match-case'])

		if self.is_comment or self.is_html_rule:
			# TODO: add support for HTML rules.
			# We should split the rule into URL and HTML parts,
			# convert URL part to a regex and parse the HTML part.
			self.regex = ''
		else:
			self.regex = self.rule_to_regex(self.rule_text)

	@classmethod
	def _split_options(cls, options_text):
		return cls.OPTIONS_SPLIT_RE.split(options_text)

	@classmethod
	def _parse_domain_option(cls, text):
		domains = text[len('domain='):]
		parts = domains.replace(',', '|').split('|')
		return dict(map(cls._parse_option_negation, parts))

	@classmethod
	def _parse_option_negation(cls, text):
		return (text.lstrip('~'), not text.startswith('~'))

	@classmethod
	def _parse_option(cls, text):
		if text.startswith("domain="):
			return ("domain", cls._parse_domain_option(text))
		return cls._parse_option_negation(text)

	@classmethod
	def rule_to_regex(cls, rule):
		"""
		Convert AdBlock rule to a regular expression.
		"""
		if not rule:
			return rule

		# Check if the rule isn't already regexp
		if rule.startswith('/') and rule.endswith('/'):
			if len(rule) > 1:
				rule = rule[1:-1]
			else:
				raise JBlockParseError('Error parsing rule.')
			return rule

		# escape special regex characters
		rule = re.sub(r"([.$+?{}()\[\]\\])", r"\\\1", rule)

		# XXX: the resulting regex must use non-capturing groups (?:
		# for performance reasons; also, there is a limit on number
		# of capturing groups, no using them would prevent building
		# a single regex out of several rules.

		# Separator character ^ matches anything but a letter, a digit, or
		# one of the following: _ - . %. The end of the address is also
		# accepted as separator.
		rule = rule.replace("^", r"(?:[^\w\d_\-.%]|$)")

		# * symbol
		rule = rule.replace("*", ".*")

		# | in the end means the end of the address
		if rule[-1] == '|':
			rule = rule[:-1] + '$'

		# || in the beginning means beginning of the domain name
		if rule[:2] == '||':
			# XXX: it is better to use urlparse for such things,
			# but urlparse doesn't give us a single regex.
			# Regex is based on http://tools.ietf.org/html/rfc3986#appendix-B
			if len(rule) > 2:
				#          |            | complete part     |
				#          |  scheme    | of the domain     |
				rule = r"^(?:[^:/?#]+:)?(?://(?:[^/?#]*\.)?)?" + rule[2:]

		elif rule[0] == '|':
			# | in the beginning means start of the address
			rule = '^' + rule[1:]

		# other | symbols should be escaped
		# we have "|$" in our regexp - do not touch it
		rule = re.sub(r"(\|)[^$]", r"\|", rule)

		return rule

	def _url_matches(self, url):
		if self.regex_re is None:
			self.regex_re = re.compile(self.regex)
		return bool(self.regex_re.search(url))

	def _domain_matches(self, domain):
		domain_rules = self.options['domain']
		for domain in _domain_variants(domain):
			if domain in domain_rules:
				return domain_rules[domain]
		return not any(domain_rules.values())

	def match_url(self, url, options=None):
		"""
		Return if this rule matches the URL.

		What to do if rule is matched is up to developer. Most likely
		``.is_exception`` attribute should be taken in account.
		"""
		options = options or {}
		for optname in self.options:
			if optname == 'match-case':  # TODO implement match-case
				continue

			if optname not in options:
				raise ValueError("Rule requires option %s" % optname)

			if optname == 'domain':
				if not self._domain_matches(options['domain']):
					return False
				continue

			if options[optname] != self.options[optname]:
				return False

		return self._url_matches(url)

	def matching_supported(self, options=None):
		"""Check if we support this rule."""
		if self.is_comment:
			return False

		if self.is_html_rule:  # TODO support html rules
			return False

		options = options or {}
		keys = set(options.keys())
		if not keys.issuperset(self._options_keys):
			# some of the required options are not given
			return False

		return True


class JBlockRules(object):
    """
    Checks multiple rules all at once.
    """

    def __init__(self, rules, supported_options=None, skip_unsupported_rules=True,
				 rule_cls=JBlockRule):

        if supported_options is None:
            self.supported_options = rule_cls.OPTIONS
        else:
            self.supported_options = supported_options

        self.rule_cls = rule_cls
        self.skip_unsupported_rules = skip_unsupported_rules

        _params = dict((opt, True) for opt in self.supported_options)
        self.rules = [
            r for r in (
                r if isinstance(r, rule_cls) else rule_cls(r)
                for r in rules
            )
            if (r.regex or r.options) and r.matching_supported(_params)
        ]

        # "advanced" rules are rules with options,
        # "basic" rules are rules without options
        advanced_rules, basic_rules = _split_iter(self.rules, lambda r: r.options)

        # Rules with domain option are handled separately:
        # if user passes a domain we can discard all rules which
        # require another domain. So we build an index:
        # {domain: [rules_which_require_it]}, and only check
        # rules which require our domain. If a rule doesn't require any
        # domain.
        # TODO: what about ~rules? Should we match them earlier?
        domain_required_rules, non_domain_rules = _split_iter(
            advanced_rules,
            lambda r: (
                'domain' in r.options
                and any(r.options["domain"].values())
            )
        )

        # split rules into blacklists and whitelists
        self.blacklist, self.whitelist = self._split_bw(basic_rules)
        _combined = functools.partial(_combined_regex)
        self.blacklist_re = _combined([r.regex for r in self.blacklist])
        self.whitelist_re = _combined([r.regex for r in self.whitelist])

        self.blacklist_with_options, self.whitelist_with_options = \
            self._split_bw(non_domain_rules)
        self.blacklist_require_domain, self.whitelist_require_domain = \
            self._split_bw_domain(domain_required_rules)

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
            for domain in _domain_variants(src_domain):
                if domain in domain_required_rules:
                    rules.extend(domain_required_rules[domain])

        rules.extend(rules_with_options)

        if self.skip_unsupported_rules:
            rules = [rule for rule in rules if rule.matching_supported(options)]

        return any(rule.match_url(url, options) for rule in rules)

    @classmethod
    def _split_bw(cls, rules):
        return _split_iter(rules, lambda r: not r.is_exception)

    @classmethod
    def _split_bw_domain(cls, rules):
        blacklist, whitelist = cls._split_bw(rules)
        return cls._domain_index(blacklist), cls._domain_index(whitelist)

    @classmethod
    def _domain_index(cls, rules):
        result = collections.defaultdict(list)
        for rule in rules:
            domains = rule.options.get('domain', {})
            for domain, required in domains.items():
                if required:
                    result[domain].append(rule)
        return dict(result)


def _domain_variants(domain):
    """
    >>> list(_domain_variants("foo.bar.example.com"))
    ['foo.bar.example.com', 'bar.example.com', 'example.com']
    >>> list(_domain_variants("example.com"))
    ['example.com']
    >>> list(_domain_variants("localhost"))
    ['localhost']
    """
    parts = domain.split('.')
    if len(parts) == 1:
        yield parts[0]
    else:
        for i in range(len(parts), 1, -1):
            yield ".".join(parts[-i:])


def _combined_regex(regexes, flags=re.IGNORECASE):
    """
    Return a compiled regex combined (using OR) from a list of ``regexes``.
    If there is nothing to combine, None is returned.
    """
    joined_regexes = "|".join(r for r in regexes if r)
    if not joined_regexes:
        return None

    return re.compile(joined_regexes, flags=flags)



def __split_iter(iterable, pred):
    """
    Split data from ``iterable`` into two lists.
    Each element is passed to function ``pred``; elements
    for which ``pred`` returns True are put into ``yes`` list,
    other elements are put into ``no`` list.

    >>> split_data(["foo", "Bar", "Spam", "egg"], lambda t: t.istitle())
    (['Bar', 'Spam'], ['foo', 'egg'])
    """
    yes, no = [], []
    for d in iterable:
        if pred(d):
            yes.append(d)
        else:
            no.append(d)
    return yes, no


def _split_iter(iterable, fn):
	"""Generate two iterables from a passed in one, one which passes pred and one which does not."""
	pass_iter, fail_iter = itertools.tee(iterable)
	return list(filter(fn, pass_iter)), list(itertools.filterfalse(fn, fail_iter))
