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

import sys, os, time
import urllib.request

from jblock import bucket

config = config  # type: ConfigAPI # noqa: F821 pylint: disable=E0602,C0103
c = c  # type: ConfigContainer # noqa: F821 pylint: disable=E0602,C0103

JBLOCK_RULES = config.datadir / "jblock-rules"

try:
	from qutebrowser.api import interceptor, cmdutils, message
	from qutebrowser.api import config as qbconfig
except ImportError:
	interceptor = None
	interceptor.Request = None

init_time = 0
blocking_time = 0
blocking_num = 0
jblock_buckets = None

if interceptor:

	@cmdutils.register()
	def jblock_update():
		page = ""
		for l in qbconfig.val.content.host_blocking.lists:
			r = urllib.request.Request(l.toString(),
									   headers={'User-Agent': 'Mozilla/5.0'})
			page += urllib.request.urlopen(r).read().decode("utf-8")
		with open(JBLOCK_RULES, "w") as f:
			f.write(page)

	@cmdutils.register()
	def jblock_reload():
		global init_time
		global jblock_buckets
		init_time = time.time()
		lines = []
		if JBLOCK_RULES.exists():
			with open(JBLOCK_RULES, "r") as f:
				lines.extend(f.readlines())
		jblock_buckets = bucket.JBlockBuckets(lines)
		init_time = time.time() - init_time

	jblock_reload()


	def jblock_intercept(info: interceptor.Request):
		global jblock_buckets
		global blocking_time
		global blocking_num
		start_time = time.time()
		request_scheme = info.request_url.scheme()
		if request_scheme == "data":
			return
		url = info.request_url.toString()
		resource_type = info.resource_type
		# TODO implement third-party
		options = {'domain': info.first_party_url.host(),
				   'script': resource_type == interceptor.ResourceType.script,
				   'image': resource_type == interceptor.ResourceType.image,
				   'stylesheet': resource_type == interceptor.ResourceType.stylesheet,
				   'object': resource_type == interceptor.ResourceType.object,
				   'subdocument': resource_type in
				   {interceptor.ResourceType.sub_frame,
					interceptor.ResourceType.sub_resource},
				   'object': resource_type == interceptor.ResourceType.object
		}
		if jblock_buckets.should_block(url, options):
			info.block()
		blocking_time += time.time() - start_time
		blocking_num += 1

	interceptor.register(jblock_intercept)

	@cmdutils.register()
	def jblock_print_buckets():
		global jblock_buckets
		message.info(jblock_buckets.summary_str())

	@cmdutils.register()
	def jblock_init_time():
		message.info(str(init_time))

	@cmdutils.register()
	def jblock_avg_block_time():
		message.info(str(blocking_time / blocking_num))

	@cmdutils.register()
	def jblock_total_block_time():
		message.info(str(blocking_time))
