"""Shared typed MCP surface for localhost server and authenticated tunnel bridge."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from mcp.types import ToolAnnotations

class SSIDChange(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    band: Literal[0,1]
    index: int=Field(ge=0,le=7)
    name: str|None=Field(default=None,min_length=1,max_length=32)
    broadcast: StrictBool|None=None

class RadioChange(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    band: Literal[0,1]
    channel: int|None=Field(default=None,ge=0,le=165)
    power_dbm: int|None=Field(default=None,ge=4,le=25)

class VLANChange(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    band: Literal[0,1]
    ssid: str=Field(min_length=1,max_length=32)
    vlan: Literal[0,30,40]

def register(mcp, backend):
    read=ToolAnnotations(readOnlyHint=True,destructiveHint=False,openWorldHint=False)
    preview=ToolAnnotations(readOnlyHint=False,destructiveHint=False,openWorldHint=False)
    write=ToolAnnotations(readOnlyHint=False,destructiveHint=True,idempotentHint=False,openWorldHint=False)
    @mcp.tool(annotations=read)
    def eap_inventory() -> dict:
        """READ: pinned EAP610 identity, health and current firmware. No secrets."""
        return backend.call('inventory',{})
    @mcp.tool(annotations=read)
    def eap_wireless() -> dict:
        """READ: both radios, SSIDs and existing VLAN assignments. Passwords redacted."""
        return backend.call('wireless',{})
    @mcp.tool(annotations=read)
    def eap_clients() -> dict:
        """READ: connected wireless clients, signal, rate and traffic."""
        return backend.call('clients',{})
    @mcp.tool(annotations=read)
    def eap_capabilities() -> dict:
        """READ: exact verification status, approval requirements and supported operations."""
        return backend.call('capabilities',{})
    @mcp.tool(annotations=preview)
    def eap_backup() -> dict:
        """READ/export: save a private AP configuration backup on the Pi. Never return backup contents."""
        return backend.call('backup',{})
    @mcp.tool(annotations=preview)
    def eap_preview_led(enabled: StrictBool) -> dict:
        """PREVIEW only: LED change. Requires separate operator approval before apply."""
        return backend.call('preview_led',{'enabled':enabled})
    @mcp.tool(annotations=preview)
    def eap_preview_ssid(change: SSIDChange) -> dict:
        """PREVIEW only: rename an existing SSID or change broadcast. Preserve passwords/security/VLANs. Local unlock required."""
        return backend.call('preview_ssid',{'change':change.model_dump()})
    @mcp.tool(annotations=preview)
    def eap_preview_radio(change: RadioChange) -> dict:
        """PREVIEW only: channel or transmit power, preserving other settings. Local unlock required."""
        return backend.call('preview_radio',{'change':change.model_dump()})
    @mcp.tool(annotations=preview)
    def eap_preview_vlan(change: VLANChange) -> dict:
        """PREVIEW only: existing SSID assignment to untagged/30/40. Never modify management VLAN or switch/gateway. Local unlock required."""
        return backend.call('preview_vlan',{'change':change.model_dump()})
    @mcp.tool(annotations=write)
    def eap_apply_change(change_id: str, confirmation: str) -> dict:
        """WRITE: apply an unexpired exact preview. Separate LOCAL approval record required, plus local unlock for wireless changes. Private backup, drift checks and verification are mandatory. Confirmation must equal APPLY <change_id>."""
        return backend.call('apply',{'change_id':change_id,'confirmation':confirmation})
    @mcp.tool(annotations=preview)
    def eap_preview_rollback(change_id: str) -> dict:
        """PREVIEW only: inverse of a previously applied change, if configuration has not drifted. Requires a new approval and appropriate local unlock."""
        return backend.call('preview_rollback',{'change_id':change_id})
