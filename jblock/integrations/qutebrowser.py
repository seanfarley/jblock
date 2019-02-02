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

"""jblock integration into qutebrowser."""

## TODO FIXME make config-source not be super painful

import sys
import os

from jblock import bucket

try:
	from qutebrowser.api import interceptor
except ImportError:
	interceptor = None
	interceptor.Request = None

def _init_jblock():
	lines = []
	with open(os.path.join(sys.path[0], "../../tests/data/easylist.txt"), "r") as f:
		lines.extend(f.readlines())
	return bucket.JBlockBuckets(lines)

jblock_buckets = _init_jblock()


if interceptor:
	def jblock_intercept(info: interceptor.Request):
		url = info.request_url.toString()
		options = {'domain': info.first_party_url.host()}
		if jblock_buckets.should_block(url, options):
			info.block()

	interceptor.register(jblock_intercept)
