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

import sys, os, time, pickle, threading
import urllib.request

from jblock import bucket, tools

# Since this is a qb integration, we get PyQt5 for free
from PyQt5.QtCore import QTimer

config = config  # type: ConfigAPI # noqa: F821 pylint: disable=E0602,C0103
c = c  # type: ConfigContainer # noqa: F821 pylint: disable=E0602,C0103

JBLOCK_RULES = config.datadir / "jblock-rules"
JBLOCK_FREQ = config.datadir / "jblock-freq"
# 1 hour in s
JBLOCK_PERIODIC_TIME = 1 * 60 * 60

from qutebrowser.api import interceptor, cmdutils, message
from qutebrowser.api import config as qbconfig

init_time = 0
blocking_time = 0
blocking_num = 0
jblock_buckets = None

@cmdutils.register()
def jblock_update():
	"""Pull adblock lists from the internet onto disk."""
	page = ""
	for l in qbconfig.val.content.host_blocking.lists:
		r = urllib.request.Request(l.toString(),
									headers={'User-Agent': 'Mozilla/5.0'})
		page += urllib.request.urlopen(r).read().decode("utf-8")
	with open(JBLOCK_RULES, "w") as f:
		f.write(page)

@cmdutils.register()
def jblock_reload():
	"""Reload jblock rules from disk."""
	global init_time
	global jblock_buckets
	init_time = time.perf_counter()
	lines = []
	if JBLOCK_RULES.exists():
		with open(JBLOCK_RULES, "r") as f:
			lines.extend(f.readlines())

	freq = None
	if JBLOCK_FREQ.exists():
		with open(JBLOCK_FREQ, "rb") as f:
			freq = pickle.load(f)

	jblock_buckets = bucket.JBlockBuckets(lines, token_frequency=freq)
	init_time = time.perf_counter() - init_time

# Handle loading/saving token frequency
@cmdutils.register()
def jblock_save_frequency():
	"""Save token frequency values to disk. Does not reload them into the current instance."""
	global jblock_buckets
	freq = jblock_buckets.get_token_frequency()
	with open(JBLOCK_FREQ, "wb") as f:
		pickle.dump(freq, f)

@cmdutils.register()
def jblock_reset_frequency():
	"""Reset frequency counters, useful if browsing habits have dramatically changed."""
	global jblock_buckets
	jblock_buckets.reset_token_frequency()

# First time init
jblock_reload()

# Handle loading/saving token frequency
@cmdutils.register()
def jblock_print_frequency(quiet=False):
	"""Print a string representation of the current frequency data."""
	global jblock_buckets
	freq = jblock_buckets.get_token_frequency()
	message.info(str(freq))

def jblock_intercept(info: interceptor.Request):
	global jblock_buckets
	global blocking_time
	global blocking_num
	start_time = time.perf_counter()
	request_scheme = info.request_url.scheme()
	if request_scheme in {"data", "blob"}:
		return

	request_host, context_host  = info.request_url.host(), info.first_party_url.host()
	first_party = tools.get_first_party_domain(context_host) == tools.get_first_party_domain(request_host)

	url = info.request_url.toString()
	resource_type = info.resource_type
	options = {
		'domain': context_host,
		'script': resource_type == interceptor.ResourceType.script,
		'image': resource_type == interceptor.ResourceType.image,
		'stylesheet': resource_type == interceptor.ResourceType.stylesheet,
		'object': resource_type == interceptor.ResourceType.object,
		'subdocument': resource_type in
		{interceptor.ResourceType.sub_frame,
			interceptor.ResourceType.sub_resource},
		'object': resource_type == interceptor.ResourceType.object,
		'document': resource_type == interceptor.ResourceType.main_frame,
		'third-party': not first_party,}
	if jblock_buckets.should_block(url, options):
		info.block()
	blocking_time += time.perf_counter() - start_time
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


# Code that will run periodically
def _periodic_callback():
	jblock_save_frequency()
	t = threading.Timer(JBLOCK_PERIODIC_TIME, _periodic_callback)
	t.daemon = True
	t.start()
_periodic_callback()
