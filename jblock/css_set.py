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

"""A set of css rules that can be built into a content blocking script"""

import json, jinja2, pathlib, os, typing

class CssSet():
	def __init__(self) -> None:
		self.general_rules = []  # type: typing.List[str]
		templateLoader = jinja2.FileSystemLoader(
			searchpath=os.path.join(os.path.dirname(__file__),"templates"))
		self.template_env = jinja2.Environment(loader=templateLoader)

	def add_rule(self, rule: str) -> None:
		if '#?#' in rule or '#@#' in rule:
			# Ignore, unsupported
			return
		if '##' not in rule:
			# Not a css rule
			raise ValueError("Not a css rule.")

		# We do not support any domain rules at all.
		if not rule.startswith('##'):
			return
		_, _, css_selector = rule.partition('##')
		self.general_rules.append(css_selector)

	def clear(self) -> None:
		"""Clear out this css set."""
		self.general_rules = []

	def gen_greasemonkey_file(self, path: pathlib.Path) -> None:
		"""Generate a greasemonkey script for this cssset at PATH"""
		s = self.gen_greasemonkey_str()
		with open(path, "w") as f:
			f.write(s)

	def gen_greasemonkey_str(self) -> str:
		"""Generate a greasemonkey script for this cssset, as a string"""
		temp = self.template_env.get_template("greasemonkey.js")
		return temp.render(general_css=self._gen_css())

	def _gen_css(self) -> str:
		"""Generate (general) css from this ruleset"""
		return ",".join(self.general_rules) + "{display:none !important;}"
