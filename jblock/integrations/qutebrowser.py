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

## --- SETTTINGS ---

## TODO FIXME make config-source not be super painful

import sys, os, time, pickle, threading, heapq
import urllib.request

from jblock import bucket
from jblock.vendor.fpdomain import fpdomain

# Since this is a qb integration, we get PyQt5 for free
from PyQt5.QtCore import QTimer

config = config  # type: ConfigAPI # noqa: F821 pylint: disable=E0602,C0103
c = c  # type: ConfigContainer # noqa: F821 pylint: disable=E0602,C0103

JBLOCK_RULES = config.datadir / "jblock-rules"
JBLOCK_FREQ = config.datadir / "jblock-freq"
PSL_FILE = config.datadir / "psl"
JBLOCK_GREASEMONKEY = config.datadir / "greasemonkey" / "jblock-content-block.js"
# 1 hour in s
JBLOCK_PERIODIC_TIME = 1 * 60 * 60
JBLOCK_SLOWEST_URL_WINDOW = 10

from qutebrowser.api import interceptor, cmdutils, message
from qutebrowser.api import config as qbconfig

init_time = 0
blocking_time = 0
blocking_num = 0
jblock_buckets = None
slowest_urls = []
psl = None

@cmdutils.register()
def jblock_update():
	"""Pull adblock lists from the internet onto disk."""
	global psl
	page = ""
	for l in qbconfig.val.content.host_blocking.lists:
		r = urllib.request.Request(l.toString(),
									headers={'User-Agent': 'Mozilla/5.0'})
		page += urllib.request.urlopen(r).read().decode("utf-8")
	with open(JBLOCK_RULES, "w") as f:
		f.write(page)

	psl.update(PSL_FILE)

@cmdutils.register()
def jblock_reload():
	"""Reload jblock rules from disk."""
	global init_time
	global jblock_buckets
	global psl
	init_time = time.perf_counter()
	lines = []
	if JBLOCK_RULES.exists():
		with open(JBLOCK_RULES, "r") as f:
			lines = f.readlines()

	freq = None
	if JBLOCK_FREQ.exists():
		with open(JBLOCK_FREQ, "rb") as f:
			freq = pickle.load(f)

	jblock_buckets = bucket.JBlockBuckets(lines, token_frequency=freq)
	init_time = time.perf_counter() - init_time

	# initialize PSL
	psl = fpdomain.PSL(PSL_FILE)


# Handle loading/saving token frequency
@cmdutils.register()
def jblock_save_frequency():
	"""Save token frequency values to disk. Does not reload them into the current instance."""
	global jblock_buckets
	if jblock_buckets is None:
		return
	freq = jblock_buckets.get_token_frequency()
	with open(JBLOCK_FREQ, "wb") as f:
		pickle.dump(freq, f)

@cmdutils.register()
def jblock_reset_frequency():
	"""Reset frequency counters, useful if browsing habits have dramatically changed."""
	global jblock_buckets
	if jblock_buckets is None:
		return
	jblock_buckets.reset_token_frequency()

# Handle loading/saving token frequency
@cmdutils.register()
def jblock_print_frequency(quiet=False):
	"""Print a string representation of the current frequency data."""
	global jblock_buckets
	if jblock_buckets is None:
		return
	freq = jblock_buckets.get_token_frequency()
	message.info(str(freq))

def jblock_intercept(info: interceptor.Request):
	global jblock_buckets
	global blocking_time
	global blocking_num
	global slowest_urls
	global psl
	# we may be making the first request.

	# We don't pre-initialize buckets as when starting qutebrowser over IPC, config is run first.
	# We only want to add overhead to the main instance.
	if jblock_buckets is None:
		# First time init
		jblock_reload()

	start_time = time.perf_counter()
	request_scheme = info.request_url.scheme()
	if info.is_blocked or request_scheme in {"data", "blob"}:
		# Don't do anything if we are already blocked or a internal url
		return

	request_host, context_host  = info.request_url.host(), info.first_party_url.host()
	first_party = psl.fp_domain(context_host) == psl.fp_domain(request_host)

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
		'document': resource_type == interceptor.ResourceType.main_frame,
		'third-party': not first_party,}
	if jblock_buckets.should_block(url, options):
		info.block()
	time_change = time.perf_counter() - start_time
	blocking_time += time_change
	blocking_num += 1
	heapq.heappush(slowest_urls, (time_change, url))
	if len(slowest_urls) > JBLOCK_SLOWEST_URL_WINDOW:
		heapq.heappop(slowest_urls)

interceptor.register(jblock_intercept)

@cmdutils.register()
def jblock_print_buckets():
	"""Print a summary of the hottest buckets."""
	global jblock_buckets
	if jblock_buckets is None:
		return
	message.info(jblock_buckets.summary_str())

@cmdutils.register()
def jblock_print_init_time():
	"""Print initialization time."""
	message.info(str(init_time))

@cmdutils.register()
def jblock_print_avg_block_time():
	"""Print the average amount of time spent blocking."""
	message.info(str(blocking_time / blocking_num))

@cmdutils.register()
def jblock_print_total_block_time():
	"""Print the total amount of time spent blocking."""
	message.info(str(blocking_time))

@cmdutils.register()
def jblock_print_slowest_urls():
	"""Print the urls that we spent the most time handling."""
	message.info(str(sorted(slowest_urls, reverse=True)))

# Code that will run periodically
def _periodic_callback():
	global jblock_buckets
	if jblock_buckets is not None:
		jblock_save_frequency()
	t = threading.Timer(JBLOCK_PERIODIC_TIME, _periodic_callback)
	t.daemon = True
	t.start()
_periodic_callback()
