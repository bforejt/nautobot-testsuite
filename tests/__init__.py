"""CI test battery: stdlib-only, no Nautobot/netmiko/requests required.

Run from the repo root::

    python3 -m unittest discover -s tests -v

Every test module imports jobs code through ``tests._loader`` so that
jobs/__init__.py (which imports Nautobot) is never executed.
"""
