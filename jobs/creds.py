"""Device credentials from Nautobot Secrets Groups — never from job inputs.

Cascade order is transport-aware (nautobot-upgrades pattern, TYPE_SSH added
for CLI devices). A missing association falls through to the next access
type; any other error (provider down, decryption failure) aborts loudly with
the group and access type named — never masked as "secret not found".
"""

from nautobot.extras.choices import SecretsGroupAccessTypeChoices, SecretsGroupSecretTypeChoices
from nautobot.extras.models.secrets import SecretsGroupAssociation


class CredentialsError(Exception):
    """Credentials could not be resolved; message is operator-facing."""


def _access_types(transport):
    """Candidate access types, most specific first, built defensively so older
    Nautobots without a given choice still work."""
    if transport == "ssh":
        names = ("TYPE_SSH", "TYPE_GENERIC")
    else:  # restconf / http
        names = ("TYPE_RESTCONF", "TYPE_HTTP", "TYPE_REST", "TYPE_GENERIC")
    types = []
    for name in names:
        value = getattr(SecretsGroupAccessTypeChoices, name, None)
        if value is not None:
            types.append(value)
    return types


def resolve_credentials(device, transport, override_group=None):
    """Return (username, password) for a device from its SecretsGroup.

    ``override_group`` (a SecretsGroup) applies one group to the whole run —
    the per-job secret the team asked for. Falls back to device.secrets_group.
    """
    group = override_group or device.secrets_group
    if group is None:
        raise CredentialsError(
            "%s has no Secrets Group assigned and no override was provided." % (device.name,)
        )
    username = _secret(group, device, SecretsGroupSecretTypeChoices.TYPE_USERNAME, transport)
    password = _secret(group, device, SecretsGroupSecretTypeChoices.TYPE_PASSWORD, transport)
    if username is None or password is None:
        raise CredentialsError(
            "Secrets group %r has no username/password association usable for %s access."
            % (group.name, transport)
        )
    return username, password


def _secret(group, device, secret_type, transport):
    for access_type in _access_types(transport):
        try:
            return group.get_secret_value(
                access_type=access_type, secret_type=secret_type, obj=device
            )
        except SecretsGroupAssociation.DoesNotExist:
            continue
        except Exception as exc:  # provider/decrypt failure: abort loudly, never mask
            raise CredentialsError(
                "Secrets group %r failed for %s/%s: %s"
                % (group.name, access_type, secret_type, exc)
            ) from exc
    return None
