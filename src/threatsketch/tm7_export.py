"""Export a Threat Dragon model as a Microsoft TMT `.tm7` file. SPEC section 14. PLAN task 4.3.

`export_tm7(raw, template_path=None) -> (xml text, warnings)`

TMT reads `.tm7` with .NET's DataContractSerializer, which is strict about element names, order
and namespaces, so this writes the exact shape of a real TMT 7.3 file. The embedded KnowledgeBase
is transcribed from the `.tb7` template. TMT-only details Threat Dragon cannot hold (flow anchor
points and ports, diagram ids, threat timestamps) come from what `import` kept under `tdtm`
keys, or are derived from the geometry. An imported model exports back to the same file
(`tests/test_tm7.py`); a model drawn in Threat Dragon needs TMT itself to confirm.
"""

from __future__ import annotations

import re
import uuid
import xml.etree.ElementTree as ET
from dataclasses import replace
from xml.sax.saxutils import escape

from .merge import fingerprint
from .model import Kind
from .resolve import resolve
from .rules.tb7 import load_template
from .td_adapter import load_raw

ABS = "http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts"
ARR = "http://schemas.microsoft.com/2003/10/Serialization/Arrays"
KB = "http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase"
SER = "http://schemas.microsoft.com/2003/10/Serialization/"
XS = "http://www.w3.org/2001/XMLSchema"
IFACES = "http://schemas.datacontract.org/2004/07/ThreatModeling.Interfaces"
OM = "http://schemas.datacontract.org/2004/07/ThreatModeling.ExternalStorage.OM"
XSI_NIL = "{http://www.w3.org/2001/XMLSchema-instance}nil"
OUT_OF_SCOPE = "71f3d9aa-b8ef-4e54-8126-607a1d903103"
OUT_OF_SCOPE_REASON = "752473b6-52d4-4776-9a24-202153f7d579"
DATAFLOW_ORDER = "15ccd509-98eb-49ad-b9c2-b4a2926d1780"
XTYPE = {  # GenericTypeId -> TMT drawing class
    "GE.P": "StencilEllipse",
    "GE.EI": "StencilRectangle",
    "GE.DS": "StencilParallelLines",
    "GE.TB.B": "BorderBoundary",
    "GE.DF": "Connector",
    "GE.TB.L": "LineBoundary",  # [unverified]: no line boundary in the sample file
}
TMT_STATE = {"Mitigated": "Mitigated", "NotApplicable": "NotApplicable"}
GUID = re.compile(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")
NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/ElikplimSunu/tdtm/tm7")  # frozen


def _t(text) -> str:
    return escape(str(text))


def _el(tag: str, text, ns: str | None = None) -> str:
    """<tag>text</tag>, <tag/> when empty, <tag i:nil="true"/> when None."""
    xmlns = f' xmlns="{ns}"' if ns else ""
    if text is None:
        return f'<{tag} i:nil="true"{xmlns}/>'
    return f"<{tag}{xmlns}>{_t(text)}</{tag}>" if str(text) != "" else f"<{tag}{xmlns}/>"


def _guid(cell_id: str) -> str:
    return cell_id if GUID.fullmatch(cell_id) else str(uuid.uuid5(NAMESPACE, cell_id))


def _num(v) -> str:
    v = float(v)
    return str(int(v)) if v.is_integer() else repr(v)


# --- the embedded KnowledgeBase, transcribed from a .tb7 ---------------------------------


def _x(e: ET.Element, tag: str) -> str | None:
    """Text of `tag`: None (written as nil) when the .tb7 lacks it, "" when it is empty."""
    return e.findtext(tag)


def _kb_attribute(a: ET.Element) -> str:
    values = "".join(_el("b:Value", v.text or "") for v in a.findall("AttributeValues/Value"))
    return (
        "<a:Attribute><a:IsExtension>false</a:IsExtension>"
        + (
            f'<a:AttributeValues xmlns:b="{IFACES}">{values}</a:AttributeValues>'
            if values
            else f'<a:AttributeValues xmlns:b="{IFACES}"/>'
        )
        + _el("a:DisplayName", _x(a, "DisplayName"))
        + _el("a:Inheritance", _x(a, "Inheritance"))
        + _el("a:Mode", _x(a, "Mode"))
        + _el("a:Name", _x(a, "Name"))
        + _el("a:Type", _x(a, "Type"))
        + "</a:Attribute>"
    )


def _kb_element(e: ET.Element) -> str:
    attrs = "".join(_kb_attribute(a) for a in e.findall("Attributes/Attribute"))
    return (
        "<a:ElementType><a:IsExtension>false</a:IsExtension>"
        + (f"<a:Attributes>{attrs}</a:Attributes>" if attrs else "<a:Attributes/>")
        + f'<a:AvailableToBaseModels xmlns:b="{OM}"/>'
        + '<a:Behavior i:nil="true"/>'
        + _el("a:Description", _x(e, "Description"))
        + _el("a:Hidden", _x(e, "Hidden"))
        + _el("a:Id", _x(e, "ID"))
        + _el("a:ImageLocation", _x(e, "ImageLocation"))
        + _el("a:ImageSource", _x(e, "Image"))
        + '<a:ImageStream i:nil="true"/>'
        + _el("a:Name", _x(e, "Name"))
        + _el("a:ParentId", _x(e, "ParentElement"))
        + _el("a:Representation", _x(e, "Representation"))
        + '<a:Shape i:nil="true"/>'
        + "<a:StencilConstraints><a:StencilConstraint><a:IsExtension>false</a:IsExtension>"
        + "<a:SelectedStencilConnection>Any</a:SelectedStencilConnection>"
        + "<a:SelectedStencilType>Any</a:SelectedStencilType></a:StencilConstraint>"
        + "</a:StencilConstraints></a:ElementType>"
    )


def _kb_metadatum(m: ET.Element) -> str:
    values = m.find("Values")
    if values is None:
        vals = f'<Values i:nil="true" xmlns:b="{ARR}"/>'
    else:
        items = "".join(
            '<b:string i:nil="true"/>'
            if v.get(XSI_NIL) == "true"
            else _el("b:string", v.text or "")
            for v in values.findall("Value")
        )
        vals = (
            f'<Values xmlns:b="{ARR}">{items}</Values>' if items else f'<Values xmlns:b="{ARR}"/>'
        )
    return (
        "<ThreatMetaDatum>"
        + _el("Name", _x(m, "Name"))
        + _el("Label", _x(m, "Label"))
        + _el("HideFromUI", _x(m, "HideFromUI"))
        + vals
        + _el("Id", m.findtext("Id"))
        + _el("AttributeType", _x(m, "AttributeType"))
        + "</ThreatMetaDatum>"
    )


def _kb_threat_type(tt: ET.Element) -> str:
    metadata = "".join(_kb_metadatum(m) for m in tt.findall("PropertiesMetaData/ThreatMetaDatum"))
    return (
        "<a:ThreatType><a:IsExtension>false</a:IsExtension>"
        + _el("a:Category", _x(tt, "Category"))
        + _el("a:Description", tt.findtext("Description") or "")
        + "<a:GenerationFilters>"
        + _el("a:Exclude", tt.findtext("GenerationFilters/Exclude") or "")
        + _el("a:Include", tt.findtext("GenerationFilters/Include") or "")
        + "</a:GenerationFilters>"
        + _el("a:Id", _x(tt, "Id"))
        + f"<a:PropertiesMetaData>{metadata}</a:PropertiesMetaData>"
        + _el("a:RelatedCategory", _x(tt, "RelatedCategory"))
        + _el("a:ShortTitle", _x(tt, "ShortTitle"))
        + "</a:ThreatType>"
    )


def knowledge_base(tb7: ET.Element, z_id: int) -> str:
    m = tb7.find("Manifest")
    meta = tb7.find("ThreatMetaData")
    cats = "".join(
        "<a:ThreatCategory><a:IsExtension>false</a:IsExtension>"
        + _el("a:Id", _x(c, "Id"))
        + _el("a:LongDescription", _x(c, "LongDescription"))
        + _el("a:Name", _x(c, "Name"))
        + _el("a:ShortDescription", _x(c, "ShortDescription"))
        + "</a:ThreatCategory>"
        for c in tb7.findall("ThreatCategories/ThreatCategory")
    )
    return (
        f'<KnowledgeBase z:Id="i{z_id}" xmlns:a="{KB}" xmlns:z="{SER}">'
        + "<a:GenericElements>"
        + "".join(_kb_element(e) for e in tb7.findall("GenericElements/ElementType"))
        + "</a:GenericElements><a:Manifest>"
        + _el("a:Author", m.get("author", ""))
        + _el("a:Id", m.get("id", ""))
        + _el("a:Name", m.get("name", ""))
        + _el("a:Version", m.get("version", ""))
        + "</a:Manifest><a:StandardElements>"
        + "".join(_kb_element(e) for e in tb7.findall("StandardElements/ElementType"))
        + f"</a:StandardElements><a:ThreatCategories>{cats}</a:ThreatCategories>"
        + "<a:ThreatMetaData>"
        + _el("IsPriorityUsed", _x(meta, "IsPriorityUsed"))
        + _el("IsStatusUsed", _x(meta, "IsStatusUsed"))
        + "<PropertiesMetaData>"
        + "".join(_kb_metadatum(d) for d in meta.findall("PropertiesMetaData/ThreatMetaDatum"))
        + "</PropertiesMetaData></a:ThreatMetaData><a:ThreatTypes>"
        + "".join(_kb_threat_type(tt) for tt in tb7.findall("ThreatTypes/ThreatType"))
        + "</a:ThreatTypes></KnowledgeBase>"
    )


# --- element properties -------------------------------------------------------------------


def _p_header(display: str) -> str:
    return (
        f'<a:anyType i:type="b:HeaderDisplayAttribute" xmlns:b="{KB}">'
        f'{_el("b:DisplayName", display)}<b:Name/><b:Value i:nil="true"/></a:anyType>'
    )


def _p_value(kind: str, display: str, name: str, value: str, xs_type: str) -> str:
    v = (
        f'<b:Value i:type="c:{xs_type}" xmlns:c="{XS}">{_t(value)}</b:Value>'
        if value != ""
        else f'<b:Value i:type="c:{xs_type}" xmlns:c="{XS}"/>'
    )
    return (
        f'<a:anyType i:type="b:{kind}" xmlns:b="{KB}">{_el("b:DisplayName", display)}'
        f"{_el('b:Name', name)}{v}</a:anyType>"
    )


def _p_list(kind: str, a, index: int) -> str:
    values = "".join(_el("a:string", v) for v in a.values)
    return (
        f'<a:anyType i:type="b:{kind}" xmlns:b="{KB}">{_el("b:DisplayName", a.display_name)}'
        f'{_el("b:Name", a.name)}<b:Value i:type="a:ArrayOfstring">{values}</b:Value>'
        f"<b:SelectedIndex>{index}</b:SelectedIndex></a:anyType>"
    )


def _properties(e, template) -> str:
    stencil = template.stencils[e.stencil]
    generic = template.stencils[stencil.root]
    data = e.td_props
    parts = [
        _p_header(stencil.name),
        _p_value("StringDisplayAttribute", "Name", "", e.name, "string"),
    ]
    if e.kind in (Kind.FLOW, Kind.BOUNDARY_BOX, Kind.BOUNDARY_CURVE):
        order = ((data.get("tdtm") or {}).get("tm7") or {}).get("dataflowOrder", "0")
        parts.append(
            _p_value("StringDisplayAttribute", "Dataflow Order", DATAFLOW_ORDER, order, "string")
        )
    if e.kind in (Kind.BOUNDARY_BOX, Kind.BOUNDARY_CURVE):
        area = "Trust Boundary Area" if e.kind is Kind.BOUNDARY_BOX else "Trust Boundary Line"
        return "".join(parts) + _p_header(area)  # [unverified for curves]
    parts.append(
        _p_value(
            "BooleanDisplayAttribute",
            "Out Of Scope",
            OUT_OF_SCOPE,
            "true" if e.out_of_scope else "false",
            "boolean",
        )
    )
    parts.append(
        _p_value(
            "StringDisplayAttribute",
            "Reason For Out Of Scope",
            OUT_OF_SCOPE_REASON,
            data.get("reasonOutOfScope") or "",
            "string",
        )
    )
    attrs = template.attributes_for(e.stencil)
    static = [a for a in attrs.values() if a.static]
    if static:
        parts.append(_p_header("Predefined Static Attributes"))
        parts += [_p_list("StaticListDisplayAttribute", a, 0) for a in static]
    parts.append(_p_header("Configurable Attributes"))

    def dynamic(names):
        for n in names:
            a = attrs[n]
            value = e.attributes.get(n, a.default)
            parts.append(_p_list("ListDisplayAttribute", a, a.values.index(value)))

    own = [n for n in stencil.own_attributes if not attrs[n].static and n in attrs]
    if stencil.id != generic.id:
        dynamic(own)  # [unverified]: placement of a stencil's own attributes
        parts.append(_p_header(f"As {generic.name}"))
    inherited = [n for n in template.attributes_for(generic.id) if not attrs[n].static]
    dynamic(inherited if stencil.id != generic.id else [n for n in attrs if not attrs[n].static])
    return "".join(parts)


# --- drawing surfaces and threats -----------------------------------------------------------


def _value(e, template, z: int, geometry: str) -> str:
    generic = template.stencils[e.stencil].root
    return (
        f"<a:KeyValueOfguidanyType><a:Key>{_guid(e.cell_id)}</a:Key>"
        f'<a:Value z:Id="i{z}" i:type="{XTYPE[generic]}">'
        f"{_el('GenericTypeId', generic, ABS)}{_el('Guid', _guid(e.cell_id), ABS)}"
        f'<Properties xmlns="{ABS}">{_properties(e, template)}</Properties>'
        f"{_el('TypeId', e.stencil, ABS)}{geometry}</a:Value></a:KeyValueOfguidanyType>"
    )


def _border_geometry(e) -> str:
    keep = (e.td_props.get("tdtm") or {}).get("tm7", {})
    r = e.rect
    dash = keep.get("strokeDashArray")
    return (
        _el("Height", _num(r.height), ABS)
        + _el("Left", _num(r.x), ABS)
        + (
            f'<StrokeDashArray i:nil="true" xmlns="{ABS}"/>'
            if dash is None
            else _el("StrokeDashArray", dash, ABS)
        )
        + _el("StrokeThickness", keep.get("strokeThickness", "0"), ABS)
        + _el("Top", _num(r.y), ABS)
        + _el("Width", _num(r.width), ABS)
    )


def _port(rect, p) -> str:
    """TMT's name for the side of `rect` that point `p` sits on."""
    c = rect.centre
    dx, dy = (p.x - c.x) / (rect.width or 1), (p.y - c.y) / (rect.height or 1)
    ns = "North" if dy < -0.25 else "South" if dy > 0.25 else ""
    ew = "West" if dx < -0.25 else "East" if dx > 0.25 else ""
    return (ns + ew) or "East"


def _line_geometry(d, f, src_id, tgt_id) -> str:
    from .diagram import _flow_points

    keep = (f.td_props.get("tdtm") or {}).get("tm7", {})
    if f.kind is Kind.FLOW:
        src, tgt = d.elements[src_id], d.elements[tgt_id]
        pts = _flow_points(d, replace(f, source_id=src_id, target_id=tgt_id))
        start, end = pts[0], pts[-1]
        ports = keep.get("ports") or [_port(src.rect, start), _port(tgt.rect, end)]
        guids = [_guid(src_id), _guid(tgt_id)]
    else:
        start, end = f.points[0], f.points[-1]
        ports, guids = ["None", "None"], ["00000000-0000-0000-0000-000000000000"] * 2
    handle = keep.get("handle") or (
        [f.points[len(f.points) // 2].x, f.points[len(f.points) // 2].y]
        if f.points
        else [(start.x + end.x) / 2, (start.y + end.y) / 2]
    )
    sx, sy = keep.get("source") or [start.x, start.y]
    tx, ty = keep.get("target") or [end.x, end.y]
    return (
        _el("HandleX", _num(handle[0]), ABS)
        + _el("HandleY", _num(handle[1]), ABS)
        + _el("PortSource", ports[0], ABS)
        + _el("PortTarget", ports[1], ABS)
        + _el("SourceGuid", guids[0], ABS)
        + _el("SourceX", _num(sx), ABS)
        + _el("SourceY", _num(sy), ABS)
        + _el("TargetGuid", guids[1], ABS)
        + _el("TargetX", _num(tx), ABS)
        + _el("TargetY", _num(ty), ABS)
    )


def _threat(
    t: dict,
    rule: str,
    src: str,
    flow: str,
    tgt: str,
    surface: str,
    flow_name: str,
    category: str,
    short: str,
) -> str:
    meta = t.get("tdtm") or {}
    keep = meta.get("tm7", {})
    status = t.get("status", "Open")
    untouched = meta.get("fingerprint") == fingerprint(t) and status == "Open"
    state = meta.get("tmtState", "").replace(" ", "") or (
        keep.get("state")
        if untouched and keep.get("state")
        else "AutoGenerated"
        if untouched
        else TMT_STATE.get(status, "NotStarted")
    )
    props = [
        ("Title", t.get("title", "")),
        ("UserThreatCategory", category),
        ("UserThreatShortDescription", short),
        ("UserThreatDescription", t.get("description", "")),
        ("InteractionString", flow_name),
        ("Priority", t.get("severity", "High")),
    ]
    p = "".join(
        f"<a:KeyValueOfstringstring><a:Key>{k}</a:Key>{_el('a:Value', v)}"
        "</a:KeyValueOfstringstring>"
        for k, v in props
    )
    return (
        f"<a:KeyValueOfstringThreatpc_P0_PhOB><a:Key>{rule}{src}{flow}{tgt}</a:Key>"
        f'<a:Value xmlns:b="{KB}">'
        + _el("b:ChangedBy", keep.get("changedBy"))
        + _el("b:DrawingSurfaceGuid", surface)
        + _el("b:FlowGuid", flow)
        + _el("b:Id", keep.get("id", t.get("number", 0)))
        + _el("b:InteractionKey", f"{src}:{flow}:{tgt}")
        + _el("b:InteractionString", keep.get("interactionString"))
        + _el("b:ModifiedAt", keep.get("modifiedAt", "0001-01-01T00:00:00"))
        + _el("b:Priority", t.get("severity", "High"))
        + f"<b:Properties>{p}</b:Properties>"
        + _el("b:SourceGuid", src)
        + _el("b:State", state)
        + _el("b:StateInformation", t.get("mitigation") or None)
        + _el("b:TargetGuid", tgt)
        + '<b:Title i:nil="true"/>'
        + _el("b:TypeId", rule)
        + "<b:Upgraded>false</b:Upgraded>"
        + '<b:UserThreatCategory i:nil="true"/><b:UserThreatDescription i:nil="true"/>'
        + '<b:UserThreatShortDescription i:nil="true"/><b:Wide>false</b:Wide>'
        + "</a:Value></a:KeyValueOfstringThreatpc_P0_PhOB>"
    )


def export_tm7(raw: dict, template_path=None) -> tuple[str, list[str]]:
    from . import DEFAULT_TEMPLATE

    tb7_path = template_path or DEFAULT_TEMPLATE
    tb7 = ET.parse(str(tb7_path)).getroot()
    template = load_template(tb7_path)
    model, doc = load_raw(raw)
    warnings = model.warnings
    errors = resolve(model, template)
    warnings += [f"tag error (default used): {e}" for e in errors]
    keep = (raw.get("tdtm") or {}).get("tm7", {})
    letters = {c.findtext("Id"): c for c in tb7.findall("ThreatCategories/ThreatCategory")}
    rule_category = {tt.id: tt.category for tt in template.threat_types}

    z, surfaces, threats = 1, [], []
    for index, d in enumerate(model.diagrams):
        if d.diagram_type != "STRIDE":
            warnings.append(f"diagram {d.title!r} ({d.diagram_type}) not exported: TMT is STRIDE")
            continue
        s_keep = (keep.get("surfaces") or {}).get(str(d.id), {})
        surface = s_keep.get("guid") or str(uuid.uuid5(NAMESPACE, f"surface:{index}:{d.title}"))
        surface_z, z = z, z + 1
        borders, lines = [], []
        for e in d.elements.values():
            if e.kind in (Kind.ACTOR, Kind.PROCESS, Kind.STORE, Kind.BOUNDARY_BOX):
                borders.append(_value(e, template, z, _border_geometry(e)))
                z += 1
        flow_ids = {}  # (cell id, direction) -> guid of the TMT connector
        for e in d.elements.values():
            if e.kind is Kind.BOUNDARY_CURVE:
                lines.append(_value(e, template, z, _line_geometry(d, e, None, None)))
                z += 1
            elif e.kind is Kind.FLOW:
                ends = [(None, e.source_id, e.target_id, e.cell_id)]
                if e.td_props.get("isBidirectional"):  # TMT has none: two connectors
                    ends = [
                        ("fwd", e.source_id, e.target_id, e.cell_id),
                        ("rev", e.target_id, e.source_id, f"{e.cell_id}:rev"),
                    ]
                for direction, s, t, key in ends:
                    alias = replace(e, cell_id=key)
                    lines.append(_value(alias, template, z, _line_geometry(d, e, s, t)))
                    flow_ids[(e.cell_id, direction)] = (_guid(key), _guid(s), _guid(t))
                    z += 1
        meta_props = _p_header("Diagram") + _p_value(
            "StringDisplayAttribute", "Name", "Name", d.title, "string"
        )
        surfaces.append(
            f'<DrawingSurfaceModel z:Id="i{surface_z}" xmlns:z="{SER}">'
            f"{_el('GenericTypeId', 'DRAWINGSURFACE', ABS)}{_el('Guid', surface, ABS)}"
            f'<Properties xmlns="{ABS}" xmlns:a="{ARR}">{meta_props}</Properties>'
            f"{_el('TypeId', 'DRAWINGSURFACE', ABS)}"
            f'<Borders xmlns:a="{ARR}">{"".join(borders)}</Borders>{_el("Header", d.title)}'
            f'<Lines xmlns:a="{ARR}">{"".join(lines)}</Lines>'
            f"{_el('Zoom', s_keep.get('zoom', '1'))}</DrawingSurfaceModel>"
        )
        for e in d.of_kind(Kind.FLOW):
            for t in doc.cells[e.cell_id]["data"].get("threats") or []:
                parts = ((t.get("tdtm") or {}).get("key") or "").split(":")
                pack, rule = parts[0], parts[1] if len(parts) > 1 else ""
                direction = parts[3] if len(parts) > 3 else None
                if pack != "sdl" or rule not in rule_category:
                    warnings.append(f"threat {t.get('title')!r} has no TMT rule; not exported")
                    continue
                if t.get("title", "").startswith("[stale] "):
                    continue
                flow, src, tgt = flow_ids[(e.cell_id, direction)]
                cat = letters[rule_category[rule]]
                pos = ((t.get("tdtm") or {}).get("tm7") or {}).get("pos", 10**9)
                threats.append(
                    (
                        pos,
                        len(threats),
                        _threat(
                            t,
                            rule,
                            src,
                            flow,
                            tgt,
                            surface,
                            e.name,
                            cat.findtext("Name"),
                            cat.findtext("ShortDescription") or "",
                        ),
                    )
                )

    meta = keep.get("meta") or {}
    summary, detail = raw.get("summary", {}), raw.get("detail", {})
    contributors = ", ".join(c.get("name", "") for c in detail.get("contributors") or [] if c)
    xml = (
        '<ThreatModel xmlns="http://schemas.datacontract.org/2004/07/ThreatModeling.Model" '
        'xmlns:i="http://www.w3.org/2001/XMLSchema-instance">'
        f"<DrawingSurfaceList>{''.join(surfaces)}</DrawingSurfaceList><MetaInformation>"
        + _el("Assumptions", meta.get("Assumptions", ""))
        + _el("Contributors", meta.get("Contributors", contributors))
        + _el("ExternalDependencies", meta.get("ExternalDependencies", ""))
        + _el("HighLevelSystemDescription", summary.get("description") or "")
        + _el("Owner", summary.get("owner") or "")
        + _el("Reviewer", detail.get("reviewer") or "")
        + _el("ThreatModelName", meta.get("ThreatModelName", summary.get("title") or ""))
        + "</MetaInformation>"
        + _el("Notes", "")
        + f'<ThreatInstances xmlns:a="{ARR}">{"".join(x for *_, x in sorted(threats))}'
        + "</ThreatInstances><ThreatGenerationEnabled>true</ThreatGenerationEnabled>"
        + f'<Validations xmlns:a="{KB}"/>'
        + _el("Version", keep.get("version", "4.3"))
        + knowledge_base(tb7, z)
        + '<Profile><PromptedKb xmlns=""/></Profile></ThreatModel>'
    )
    return xml, warnings
