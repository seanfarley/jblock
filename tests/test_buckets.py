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


import pytest

from jblock import bucket

def test_bulk_bucket_match():
	token_strs = []
	with open("tests/data/easylist.txt") as f:
		for line in f:
			token_strs.append(line)
	buckets = bucket.JBlockBuckets(token_strs)
