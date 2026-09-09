"""Nmap XML, text, and grepable output normalization."""
import ipaddress
import re
from defusedxml import ElementTree as ET


MAX_NSE_SOURCE_LOCATIONS = 64


def _nse_scripts(host, host_index):
    locations = []
    count = 0
    for script_index, _ in enumerate(host.findall('hostscript/script')):
        count += 1
        if len(locations) < MAX_NSE_SOURCE_LOCATIONS:
            locations.append(f'host[{host_index}]/hostscript/script[{script_index}]')
    for port_index, port in enumerate(host.findall('ports/port')):
        for script_index, _ in enumerate(port.findall('script')):
            count += 1
            if len(locations) < MAX_NSE_SOURCE_LOCATIONS:
                locations.append(f'host[{host_index}]/ports/port[{port_index}]/script[{script_index}]')
    return count, locations


def parse(raw, format, context):
    if format == 'nmap_xml':
        root = ET.fromstring(raw)
        if root.tag != 'nmaprun':
            raise ValueError('Expected an Nmap XML document')
        nse_count = 0
        nse_locations = []
        for hi, host in enumerate(root.findall('host')):
            host_nse_count, host_nse_locations = _nse_scripts(host, hi)
            nse_count += host_nse_count
            remaining_locations = MAX_NSE_SOURCE_LOCATIONS - len(nse_locations)
            nse_locations.extend(host_nse_locations[:remaining_locations])
            addresses = [a.get('addr') for a in host.findall('address') if a.get('addrtype') in ('ipv4', 'ipv6')]
            if not addresses:
                context.result['limitations'].append(f'Host {hi} has no IP address.')
                continue
            addr = str(ipaddress.ip_address(addresses[0]))
            context.asset(addr, addr, addresses=addresses, hostnames=[n.get('name') for n in host.findall('hostnames/hostname')])
            if host_nse_count:
                context.observed(
                    addr,
                    'Unsupported Nmap NSE script evidence was detected',
                    f'host[{hi}]',
                    script_count=host_nse_count,
                    source_locations=host_nse_locations,
                    source_locations_truncated=host_nse_count > len(host_nse_locations),
                )
            for p in host.findall('ports/port'):
                state = p.find('state')
                if state is None or state.get('state') != 'open':
                    continue
                service = p.find('service')
                attrs = service.attrib if service is not None else {}
                context.service(addr, p.get('portid'), p.get('protocol'), attrs.get('name', ''), attrs.get('product', ''), attrs.get('version', ''))
                context.observed(addr, 'Tool reported an open service', f'host[{hi}]/port[{p.get("portid")}]')
        finished = root.find('runstats/finished')
        if finished is None or finished.get('exit', 'success') != 'success':
            context.result['limitations'].append('Successful scan completion was not recorded.')
        if nse_count:
            locations = ', '.join(nse_locations)
            suffix = f' Source locations: {locations}.' if locations else ''
            if nse_count > len(nse_locations):
                suffix += f' {nse_count - len(nse_locations)} additional location(s) were omitted by the metadata limit.'
            context.result['limitations'].append(
                f'{nse_count} unsupported Nmap NSE script element(s) were detected; script attributes and output were not interpreted.' + suffix
            )
        return
    context.result['limitations'].append('Text import is lossy. XML preserves more collection context.')
    host = None
    for line_no, line in enumerate(raw.decode('utf8', 'replace').splitlines(), 1):
        if format == 'nmap_gnmap':
            match = re.match(r'Host: (\S+) .*?Ports: (.*)', line)
            if match:
                host = str(ipaddress.ip_address(match[1])); context.asset(host, host)
                for port in match[2].split(', '):
                    fields = port.split('/')
                    if len(fields) >= 5 and fields[1] == 'open':
                        context.service(host, fields[0], fields[2], fields[4])
        else:
            if line.startswith('Nmap scan report for '):
                candidate = line[21:].split()[-1].strip('()')
                try:
                    host = str(ipaddress.ip_address(candidate)); context.asset(host, host)
                except ValueError:
                    host = None
                    context.result['limitations'].append(f'Line {line_no}: no unambiguous address.')
            match = re.match(r'(\d+)/(tcp|udp|sctp)\s+open\s+(\S+)', line)
            if match and host:
                context.service(host, match[1], match[2], match[3])
