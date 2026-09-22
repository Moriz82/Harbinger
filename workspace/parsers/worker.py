"""Fixed entry point inside the networkless parser sandbox."""
import json
import os
import resource
import sys

# Append reviewed host dependencies after the standard library. Some hosts ship
# compatibility modules in site-packages with standard-library names. The
# launcher uses -S so .pth startup code and those names cannot replace stdlib.
dependency_path = os.environ.get('PARSER_PURELIB')
if dependency_path:
    sys.path.append(dependency_path)

resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
resource.setrlimit(resource.RLIMIT_CPU, (110, 110))
resource.setrlimit(resource.RLIMIT_FSIZE, (128 * 1024**2, 128 * 1024**2))
resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
from parsers import parse

try:
    with open('/input', 'rb') as source:
        data = source.read(256 * 1024**2 + 1)
    json.dump(parse(data, sys.argv[1]), sys.stdout, ensure_ascii=True, allow_nan=False)
except Exception:
    # Target-controlled exception text never crosses the boundary.
    sys.stderr.write('The parser could not accept this file. Review its format and limits.\n')
    sys.exit(2)
