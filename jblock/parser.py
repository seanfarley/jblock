
import re
import attr
import typing

class JBlockParseError(ValueError):
    pass


@attr.attributes(slots=True)
class JBlockRule():
	"""An individual rule which a URL can be matched against."""
	OPTIONS = {
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
		"domain",}

	OPTIONS_SPLIT_RE = re.compile(',(?=~?(?:%s))' % ('|'.join(OPTIONS)))

	raw_text = attr.attr(type=str)
	rule_text = attr.attr(init=False, type=str)
	regex_re = attr.attr(init=False, type=typing.Optional[typing.Pattern])

	is_comment = attr.attr(init=False, type=bool)

	@is_comment.default
	def c_init(self):
		return not self.raw_text or self.raw_text.startswith(('!', '[Adblock'))

	is_html_rule = attr.attr(init=False, type=bool)
	is_exception = attr.attr(init=False, type=bool)
	raw_options = attr.attr(init=False, type=typing.List)
	options = attr.attr(init=False, type=typing.Dict)


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
		rule = rule.replace("^", "(?:[^\w\d_\-.%]|$)")

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
		rule = re.sub("(\|)[^$]", r"\|", rule)

		return rule
