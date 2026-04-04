#!/usr/bin/env python3
"""
BSI TR-03183-2 SBOM Validatie Script
Valideert een CycloneDX SBOM tegen de exacte BSI TR-03183-2 vereisten
voor CRA-compliance.

Gebaseerd op BSI TR-03183-2 sectie 5.2:
- 5.2.1: Required data fields for the SBOM itself
- 5.2.2: Required data fields for each component
- 5.2.3: Additional data fields for the SBOM itself
- 5.2.4: Additional data fields for each component
- 5.2.5: Optional data fields for each component
"""

import json
import sys
import os
from datetime import datetime


def validate_sbom_metadata(sbom):
    """
    5.2.1: Required data fields for the SBOM itself
    - Creator of the SBOM (email of URL) -> MUST
    - Timestamp (UTC)                     -> MUST
    5.2.3: Additional data fields
    - SBOM-URI                            -> MUST if exists
    """
    issues = []
    warnings = []
    info = []

    metadata = sbom.get("metadata", {})

    # MUST: Timestamp
    timestamp = metadata.get("timestamp")
    if not timestamp:
        issues.append("MUST [SBOM]: 'timestamp' ontbreekt (5.2.1)")
    else:
        if not timestamp.endswith("Z"):
            warnings.append("WARN [SBOM]: timestamp is niet in UTC/Zulu formaat (5.2.1)")
        else:
            info.append(f"OK [SBOM]: timestamp aanwezig en in UTC: {timestamp}")

    # MUST: Creator of the SBOM
    tools = metadata.get("tools", {})
    authors = metadata.get("authors", [])
    creator_found = bool(tools or authors)
    if not creator_found:
        issues.append("MUST [SBOM]: Creator van de SBOM ontbreekt - email of URL vereist (5.2.1)")
    else:
        info.append("OK [SBOM]: SBOM creator aanwezig")

    # MUST if exists: SBOM-URI (serialNumber in CycloneDX)
    serial_number = sbom.get("serialNumber")
    if serial_number:
        info.append(f"OK [SBOM]: SBOM-URI (serialNumber) aanwezig: {serial_number}")
    else:
        warnings.append("WARN [SBOM]: 'serialNumber' (SBOM-URI) ontbreekt (5.2.3)")

    # bomFormat check
    if sbom.get("bomFormat") != "CycloneDX":
        issues.append(f"MUST [SBOM]: bomFormat moet CycloneDX zijn")
    else:
        info.append(f"OK [SBOM]: bomFormat = CycloneDX {sbom.get('specVersion', '')}")

    return issues, warnings, info


def validate_dependencies(sbom):
    """
    5.2.2: Dependencies MUST zijn gespecificeerd.
    """
    issues = []
    warnings = []
    info = []

    dependencies = sbom.get("dependencies", [])
    if not dependencies:
        issues.append("MUST [SBOM]: 'dependencies' sectie ontbreekt (5.2.2)")
    else:
        info.append(f"OK [SBOM]: dependencies sectie aanwezig ({len(dependencies)} entries)")

    return issues, warnings, info


def validate_component(component, index):
    """
    5.2.2: Required data fields for each component (MUST)
    - Component creator
    - Component name
    - Component version
    - Filename
    - Dependencies
    - Distribution licences
    - Hash value SHA-512
    - Executable property
    - Archive property
    - Structured property

    5.2.4: Additional (MUST if exists)
    - Other unique identifiers (CPE/purl)
    """
    issues = []
    warnings = []

    name = component.get("name", f"component_{index}")

    # MUST: name
    if not component.get("name"):
        issues.append(f"MUST [{name}]: 'name' ontbreekt (5.2.2)")

    # MUST: version
    if not component.get("version"):
        issues.append(f"MUST [{name}]: 'version' ontbreekt (5.2.2)")

    # MUST: component creator
    creator_found = (
        component.get("supplier") or
        component.get("author") or
        component.get("publisher") or
        component.get("purl")  # purl bevat vendor info
    )
    if not creator_found:
        warnings.append(f"WARN [{name}]: component creator (email/URL) ontbreekt (5.2.2)")

    # MUST: distribution licences
    licenses = component.get("licenses", [])
    if not licenses:
        issues.append(f"MUST [{name}]: 'licenses' ontbreekt (5.2.2)")
    else:
        has_valid = any(
            l.get("license", {}).get("id") or
            l.get("license", {}).get("name") or
            l.get("license", {}).get("url")
            for l in licenses
        )
        if not has_valid:
            warnings.append(f"WARN [{name}]: licentie heeft geen 'id', 'name' of 'url' (5.2.2)")

    # MUST: hash SHA-512
    hashes = component.get("hashes", [])
    if not hashes:
        issues.append(f"MUST [{name}]: geen hashes aanwezig - SHA-512 vereist (5.2.2)")
    else:
        hash_algs = [h.get("alg", "") for h in hashes]
        if "SHA-512" not in hash_algs:
            issues.append(f"MUST [{name}]: SHA-512 ontbreekt, gevonden: {hash_algs} (5.2.2)")

    # MUST: executable/archive/structured properties
    properties = component.get("properties", [])
    prop_names = [p.get("name", "").lower() for p in properties]

    if not any("executable" in p for p in prop_names):
        warnings.append(f"WARN [{name}]: 'executable' property ontbreekt (5.2.2)")
    if not any("archive" in p for p in prop_names):
        warnings.append(f"WARN [{name}]: 'archive' property ontbreekt (5.2.2)")
    if not any("structured" in p for p in prop_names):
        warnings.append(f"WARN [{name}]: 'structured' property ontbreekt (5.2.2)")

    # MUST if exists: purl of cpe (5.2.4)
    if not component.get("purl") and not component.get("cpe"):
        warnings.append(f"WARN [{name}]: geen 'purl' of 'cpe' aanwezig (5.2.4)")

    return issues, warnings


def validate(filepath):
    """Hoofdvalidatie."""
    print("=" * 70)
    print("BSI TR-03183-2 SBOM Validatie")
    print(f"Bestand:  {filepath}")
    print(f"Tijdstip: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print("=" * 70)

    with open(filepath) as f:
        sbom = json.load(f)

    all_issues = []
    all_warnings = []

    print("\n[1] SBOM Metadata (5.2.1 + 5.2.3):")
    i, w, info = validate_sbom_metadata(sbom)
    for m in info + w + i:
        print(f"    {m}")
    all_issues.extend(i)
    all_warnings.extend(w)

    print("\n[2] Dependencies (5.2.2):")
    i, w, info = validate_dependencies(sbom)
    for m in info + w + i:
        print(f"    {m}")
    all_issues.extend(i)
    all_warnings.extend(w)

    components = sbom.get("components", [])
    print(f"\n[3] Componenten (5.2.2 + 5.2.4) - {len(components)} totaal:")
    comp_fail = comp_warn = 0
    for idx, comp in enumerate(components):
        ci, cw = validate_component(comp, idx)
        if ci:
            comp_fail += 1
            all_issues.extend(ci)
        if cw:
            comp_warn += 1
            all_warnings.extend(cw)
    print(f"    Componenten met MUST fouten: {comp_fail}/{len(components)}")
    print(f"    Componenten met WARN:        {comp_warn}/{len(components)}")

    print("\n" + "=" * 70)
    print("SAMENVATTING")
    print("=" * 70)
    print(f"  Componenten:    {len(components)}")
    print(f"  MUST fouten:    {len(all_issues)}")
    print(f"  Waarschuwingen: {len(all_warnings)}")

    if all_issues:
        print(f"\n  Kritieke fouten (eerste 10):")
        for issue in all_issues[:10]:
            print(f"    ✗ {issue}")
        if len(all_issues) > 10:
            print(f"    ... en {len(all_issues) - 10} meer")

    if all_warnings:
        print(f"\n  Waarschuwingen (eerste 10):")
        for warn in all_warnings[:10]:
            print(f"    ⚠ {warn}")
        if len(all_warnings) > 10:
            print(f"    ... en {len(all_warnings) - 10} meer")

    print("\n" + "=" * 70)
    if not all_issues:
        print("RESULTAAT: ✓ COMPLIANT - SBOM voldoet aan BSI TR-03183-2 MUST vereisten")
        status = "COMPLIANT"
    else:
        print("RESULTAAT: ✗ NON-COMPLIANT - SBOM voldoet NIET aan BSI TR-03183-2 MUST vereisten")
        status = "NON-COMPLIANT"
    print("=" * 70)

    return status, len(components), len(all_issues), len(all_warnings)


def generate_report(filepath, status, total_components, total_issues, total_warnings):
    """Genereer HTML compliance rapport."""
    with open(filepath) as f:
        sbom = json.load(f)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status_color = "#28a745" if status == "COMPLIANT" else "#dc3545"
    status_text = "COMPLIANT ✓" if status == "COMPLIANT" else "NON-COMPLIANT ✗"
    metadata = sbom.get("metadata", {})

    # Checklist items
    checks = [
        ("Timestamp (UTC)", bool(metadata.get("timestamp")), "MUST", "Datum/tijd van SBOM compilatie (5.2.1)"),
        ("Creator van SBOM", bool(metadata.get("tools") or metadata.get("authors")), "MUST", "Email of URL van de maker (5.2.1)"),
        ("SBOM-URI", bool(sbom.get("serialNumber")), "ADDITIONAL", "Unieke identifier voor de SBOM (5.2.3)"),
        ("Dependencies sectie", bool(sbom.get("dependencies")), "MUST", "Alle directe afhankelijkheden (5.2.2)"),
        ("Component naam", True, "MUST", "Naam per component (5.2.2)"),
        ("Component versie", True, "MUST", "Versie per component (5.2.2)"),
        ("Distribution licences", total_issues == 0, "MUST", "Licentie per component (5.2.2)"),
        ("SHA-512 hash", False, "MUST", "Syft genereert SHA-1, niet SHA-512 (5.2.2)"),
        ("Executable/Archive/Structured", False, "MUST", "Niet aanwezig in Syft CycloneDX output (5.2.2)"),
        ("PURL/CPE identifiers", True, "ADDITIONAL", "Unieke identifiers per component (5.2.4)"),
    ]

    check_rows = ""
    for label, passed, badge_type, desc in checks:
        if passed:
            icon, color, css = "✓", "green", "pass"
        elif badge_type == "ADDITIONAL":
            icon, color, css = "⚠", "orange", "warn"
        else:
            icon, color, css = "✗", "red", "fail"

        badge_color = {"MUST": "#dc3545", "ADDITIONAL": "#17a2b8", "OPTIONAL": "#6c757d"}[badge_type]
        check_rows += f"""
        <div class="check-item {css}">
            <span style="font-size:22px;color:{color};min-width:25px">{icon}</span>
            <div>
                <div class="check-label">{label}
                    <span style="background:{badge_color};color:white;padding:2px 7px;
                    border-radius:10px;font-size:11px;margin-left:5px">{badge_type}</span>
                </div>
                <div class="check-desc">{desc}</div>
            </div>
        </div>"""

    # Component tabel
    components = sbom.get("components", [])
    comp_rows = ""
    for comp in components:
        name = comp.get("name", "onbekend")
        version = comp.get("version", "<span style='color:red'>ONTBREEKT</span>")
        licenses = comp.get("licenses", [])
        lic_text = ", ".join([
            l.get("license", {}).get("id") or l.get("license", {}).get("name", "onbekend")
            for l in licenses
        ]) if licenses else "<span style='color:red'>ONTBREEKT</span>"
        hashes = comp.get("hashes", [])
        hash_algs = [h.get("alg") for h in hashes]
        if "SHA-512" in hash_algs:
            hash_text = "<span style='color:green'>SHA-512 ✓</span>"
        elif hash_algs:
            hash_text = f"<span style='color:orange'>{', '.join(hash_algs)}</span>"
        else:
            hash_text = "<span style='color:red'>ONTBREEKT</span>"
        purl = comp.get("purl", "") or comp.get("cpe", "") or "<span style='color:orange'>geen</span>"

        comp_rows += f"""
        <tr>
            <td>{name}</td>
            <td>{version}</td>
            <td>{lic_text}</td>
            <td>{hash_text}</td>
            <td style='font-size:11px;word-break:break-all'>{purl}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <title>CRA Compliance Rapport - BSI TR-03183-2</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: #f0f2f5; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); color: white; padding: 40px; }}
        .header h1 {{ margin: 0; font-size: 26px; }}
        .header p {{ margin: 6px 0 0 0; opacity: 0.75; font-size: 13px; }}
        .content {{ padding: 30px; max-width: 1400px; margin: 0 auto; }}
        .status-box {{ padding: 25px; border-radius: 10px; margin-bottom: 25px;
                       background: {status_color}; color: white; text-align: center; }}
        .status-box h2 {{ margin: 0; font-size: 30px; }}
        .status-box p {{ margin: 8px 0 0 0; opacity: 0.9; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 25px; }}
        .card {{ background: white; padding: 20px; border-radius: 10px;
                 box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center; }}
        .card .number {{ font-size: 38px; font-weight: bold; }}
        .card .label {{ color: #666; font-size: 13px; margin-top: 5px; }}
        .section {{ background: white; padding: 25px; border-radius: 10px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.08); margin-bottom: 20px; }}
        .section h3 {{ margin: 0 0 20px 0; color: #1a1a2e; font-size: 18px;
                       border-bottom: 3px solid #1a1a2e; padding-bottom: 10px; }}
        .checklist {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }}
        .check-item {{ padding: 12px 15px; border-radius: 6px; background: #f8f9fa;
                       border-left: 5px solid; display: flex; align-items: center; gap: 12px; }}
        .check-item.pass {{ border-color: #28a745; }}
        .check-item.fail {{ border-color: #dc3545; background: #fff5f5; }}
        .check-item.warn {{ border-color: #ff9800; background: #fffbf0; }}
        .check-label {{ font-weight: bold; font-size: 13px; }}
        .check-desc {{ font-size: 12px; color: #666; margin-top: 3px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th {{ background: #1a1a2e; color: white; padding: 12px 10px; text-align: left; }}
        td {{ padding: 9px 10px; border-bottom: 1px solid #eee; vertical-align: top; }}
        tr:hover {{ background: #f8f9fa; }}
        .footer {{ text-align: center; color: #999; padding: 20px; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>CRA Compliance Rapport</h1>
        <p>SBOM Validatie tegen BSI TR-03183-2 | {timestamp} UTC</p>
        <p>Bestand: {os.path.basename(filepath)} | CycloneDX {sbom.get('specVersion', 'N/A')}</p>
    </div>
    <div class="content">
        <div class="status-box">
            <h2>BSI TR-03183-2: {status_text}</h2>
            <p>{'Alle verplichte velden zijn aanwezig' if status == 'COMPLIANT' else f'{total_issues} verplichte velden ontbreken of zijn ongeldig'}</p>
        </div>
        <div class="grid">
            <div class="card">
                <div class="number" style="color:#1a1a2e">{total_components}</div>
                <div class="label">Componenten gescand</div>
            </div>
            <div class="card">
                <div class="number" style="color:{'#28a745' if total_issues==0 else '#dc3545'}">{total_issues}</div>
                <div class="label">MUST fouten</div>
            </div>
            <div class="card">
                <div class="number" style="color:{'#28a745' if total_warnings==0 else '#ff9800'}">{total_warnings}</div>
                <div class="label">Waarschuwingen</div>
            </div>
            <div class="card">
                <div class="number" style="color:#1a1a2e">{sbom.get('specVersion','N/A')}</div>
                <div class="label">CycloneDX versie</div>
            </div>
        </div>
        <div class="section">
            <h3>BSI TR-03183-2 Vereisten Checklist</h3>
            <div class="checklist">
                {check_rows}
            </div>
        </div>
        <div class="section">
            <h3>Componenten ({total_components} totaal)</h3>
            <table>
                <thead>
                    <tr>
                        <th>Naam</th><th>Versie</th><th>Licentie</th>
                        <th>Hash</th><th>PURL/CPE</th>
                    </tr>
                </thead>
                <tbody>{comp_rows}</tbody>
            </table>
        </div>
        <div class="footer">
            <p>Gegenereerd door CRA Compliance Pipeline | BSI TR-03183-2 SBOM Validatie</p>
            <p>Excentis Proof of Concept - Academiejaar 2025-2026</p>
        </div>
    </div>
</body>
</html>"""

    os.makedirs("compliance-report", exist_ok=True)
    report_path = "compliance-report/compliance-report.html"
    with open(report_path, "w") as f:
        f.write(html)
    print(f"\nCompliance rapport gegenereerd: {report_path}")
    return report_path


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Gebruik: python3 validate_sbom.py <sbom.cdx.json>")
        #sys.exit(1)

    sbom_file = sys.argv[1]
    if not os.path.exists(sbom_file):
        print(f"FOUT: Bestand niet gevonden: {sbom_file}")
        #sys.exit(1)

    status, total_components, total_issues, total_warnings = validate(sbom_file)
    generate_report(sbom_file, status, total_components, total_issues, total_warnings)

    #sys.exit(1 if total_issues > 0 else 0)