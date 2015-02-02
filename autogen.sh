#!/bin/sh

set -e

libtoolize --force
autoreconf -f -i

exit 0
