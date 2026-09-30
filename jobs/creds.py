"""Device credentials from Nautobot Secrets Groups — never from job inputs.

Cascade order is transport-aware (nautobot-upgrades pattern, TYPE_SSH added
for CLI devices). A missing association falls through to the next access
type; any other error (provider down, decryption failure) aborts loudly with
the group and access type named — never masked as "secret not found".

A BMC modelled as an Interface on its host Device takes its credentials from
the Secrets Group associated with that interface through the
``bmc_secrets_group`` Relationship (``resolve_bmc_credentials``); the host's
own Secrets Group and the capture job's per-run override never apply to it.
"""

from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from nautobot.extras.choices import SecretsGroupAccessTypeChoices, SecretsGroupSecretTypeChoices
from nautobot.extras.models import Relationship, RelationshipAssociation, SecretsGroup
from nautobot.extras.models.secrets import SecretsGroupAssociation

from . import constants as C


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


def resolve_bmc_credentials(interface, device, key=C.BMC_SECRETS_RELATIONSHIP_KEY):
    """Return (username, password) for a BMC interface from its related Secrets Group.

    The Secrets Group is the other end of the one RelationshipAssociation of
    the ``key`` Relationship that has the interface at either end (the plan's
    orientation is source Secrets Group -> destination Interface; the reverse
    is accepted). The secret lookup is the HTTPS cascade with the HOST device
    as ``obj``, so templated secret providers keep working. Every failure is
    a CredentialsError naming what the operator has to fix.
    """
    relationship = Relationship.objects.filter(key=key).first()
    if relationship is None:
        raise CredentialsError(
            "no Relationship with key %r exists — create it once (Extensibility -> "
            "Relationships: key %s, type one-to-many, source extras | secrets group, "
            "destination dcim | interface), then associate the BMC's Secrets Group with "
            "interface %s of %s" % (key, key, interface.name, device.name)
        )
    interface_type = ContentType.objects.get_for_model(type(interface))
    group_type = ContentType.objects.get_for_model(SecretsGroup)
    associations = RelationshipAssociation.objects.filter(relationship=relationship).filter(
        Q(source_type=interface_type, source_id=interface.pk)
        | Q(destination_type=interface_type, destination_id=interface.pk)
    )
    group_ids = []
    for association in associations:
        if association.source_type_id == interface_type.pk and (
            association.source_id == interface.pk
        ):
            other_type, other_id = association.destination_type_id, association.destination_id
        else:
            other_type, other_id = association.source_type_id, association.source_id
        if other_type != group_type.pk:
            raise CredentialsError(
                "the %r association on interface %s of %s points at a %s, not a Secrets Group"
                % (key, interface.name, device.name, ContentType.objects.get_for_id(other_type))
            )
        if other_id not in group_ids:
            group_ids.append(other_id)
    if not group_ids:
        raise CredentialsError(
            "no %r association on interface %s of %s — associate the BMC's Secrets Group "
            "with the interface (its Relationships panel)" % (key, interface.name, device.name)
        )
    if len(group_ids) > 1:
        raise CredentialsError(
            "%d Secrets Groups are associated with interface %s of %s through %r — exactly "
            "one may be" % (len(group_ids), interface.name, device.name, key)
        )
    group = SecretsGroup.objects.get(pk=group_ids[0])
    username = _secret(group, device, SecretsGroupSecretTypeChoices.TYPE_USERNAME, "https")
    password = _secret(group, device, SecretsGroupSecretTypeChoices.TYPE_PASSWORD, "https")
    if username is None or password is None:
        raise CredentialsError(
            "Secrets group %r (the BMC's, via %r on interface %s) has no username/password "
            "association usable for https access" % (group.name, key, interface.name)
        )
    return username, password
