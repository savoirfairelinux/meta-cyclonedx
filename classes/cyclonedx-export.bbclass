# SPDX-License-Identifier: MIT
# Copyright 2022 BG Networks, Inc.
# Copyright (C) 2024 Savoir-faire Linux Inc. (<www.savoirfairelinux.com>).

# The product name that the CVE database uses.  Defaults to BPN, but may need to
# be overriden per recipe (for example tiff.bb sets CVE_PRODUCT=libtiff).
CVE_PRODUCT ??= "${BPN}"
CVE_VERSION ??= "${PV}"

CYCLONEDX_EXPORT_DIR ??= "${DEPLOY_DIR}/cyclonedx-export"
CYCLONEDX_EXPORT_SBOM ??= "${CYCLONEDX_EXPORT_DIR}/bom.json"
CYCLONEDX_EXPORT_VEX ??= "${CYCLONEDX_EXPORT_DIR}/vex.json"
CYCLONEDX_EXPORT_TMP ??= "${TMPDIR}/cyclonedx-export"
CYCLONEDX_EXPORT_LOCK ??= "${CYCLONEDX_EXPORT_TMP}/bom.lock"

# resolve CVE_CHECK_IGNORE and CVE_STATUS_GROUPS,
# taken from https://git.yoctoproject.org/poky/commit/meta/classes/cve-check.bbclass?id=be9883a92bad0fe4c1e9c7302c93dea4ac680f8c
# SPDX-License-Identifier: MIT
# Copyright (C) 2023 Andrej Valek <andrej.valek@siemens.com>

python () {
    # Fallback all CVEs from CVE_CHECK_IGNORE to CVE_STATUS
    cve_check_ignore = d.getVar("CVE_CHECK_IGNORE")
    if cve_check_ignore:
        bb.warn("CVE_CHECK_IGNORE is deprecated in favor of CVE_STATUS")
        for cve in (d.getVar("CVE_CHECK_IGNORE") or "").split():
            d.setVarFlag("CVE_STATUS", cve, "ignored")

    # Process CVE_STATUS_GROUPS to set multiple statuses and optional detail or description at once
    for cve_status_group in (d.getVar("CVE_STATUS_GROUPS") or "").split():
        cve_group = d.getVar(cve_status_group)
        if cve_group is not None:
            for cve in cve_group.split():
                d.setVarFlag("CVE_STATUS", cve, d.getVarFlag(cve_status_group, "status"))
        else:
            bb.warn("CVE_STATUS_GROUPS contains undefined variable %s" % cve_status_group)
}

python do_cyclonedx_init() {
    import uuid
    from datetime import datetime, timezone

    timestamp = datetime.now(timezone.utc).isoformat()
    sbom_dir = d.getVar("CYCLONEDX_EXPORT_DIR")
    bb.debug(2, "Creating cyclonedx directory: %s" % sbom_dir)
    bb.utils.mkdirhier(sbom_dir)

    # Generate unique serial numbers for sbom and vex document
    sbom_serial_number = str(uuid.uuid4())
    vex_serial_number = str(uuid.uuid4())

    bb.debug(2, f"Creating empty sbom file with serial number {sbom_serial_number}")
    write_json(d.getVar("CYCLONEDX_EXPORT_SBOM"), {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{sbom_serial_number}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"name": "yocto"}]
        },
        "components": []
    })

    bb.debug(2, f"Creating empty vex file with serial number {vex_serial_number}")
    write_json(d.getVar("CYCLONEDX_EXPORT_VEX"), {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{vex_serial_number}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"name": "yocto"}]
        },
        "vulnerabilities": []
    })
}
addhandler do_cyclonedx_init
do_cyclonedx_init[eventmask] = "bb.event.BuildStarted"

python do_cyclonedx_package_collect() {
    from oe.cve_check import decode_cve_status

    # ignore non-target packages
    for ignored_suffix in (d.getVar("SPECIAL_PKGSUFFIX") or "").split():
        if d.getVar("PN").endswith(ignored_suffix):
            return

    # load the bom
    name = d.getVar("CVE_PRODUCT")
    version = d.getVar("CVE_VERSION")
    sbom = read_json(d.getVar("CYCLONEDX_EXPORT_SBOM"))
    # extract the sbom serial number without "urn:uuid:" prefix
    # (avoid using builtin str.removeprefix function as Python >= 3.9 required)
    sbom_serial_number = sbom["serialNumber"][len("urn:uuid:"):]
    vex = read_json(d.getVar("CYCLONEDX_EXPORT_VEX"))

    for pkg in generate_packages_list(name, version):
        if not next((c for c in sbom["components"] if c["cpe"] == pkg["cpe"]), None):
            sbom["components"].append(pkg)
            bom_ref = pkg["bom-ref"]

            for cve in (d.getVarFlags("CVE_STATUS") or {}):
                append_to_vex_vulnerabilities(d, vex, cve, sbom_serial_number, bom_ref)
    
    # write it back to the deploy directory
    write_json(d.getVar("CYCLONEDX_EXPORT_SBOM"), sbom)
    write_json(d.getVar("CYCLONEDX_EXPORT_VEX"), vex)
}

addtask do_cyclonedx_package_collect before do_build
do_cyclonedx_package_collect[nostamp] = "1"
do_cyclonedx_package_collect[lockfiles] += "${CYCLONEDX_EXPORT_LOCK}"
do_rootfs[recrdeptask] += "do_cyclonedx_package_collect"

def read_json(path):
    import json
    from pathlib import Path
    return json.loads(Path(path).read_text())

def write_json(path, content):
    import json
    from pathlib import Path
    Path(path).write_text(
        json.dumps(content, indent=2)
    )

def generate_packages_list(products_names, version):
    """
    Get a list of products and generate CPE and PURL identifiers for each of them.
    """
    import uuid

    packages = []

    # keep only the short version which can be matched against vulnerabilities databases
    version = version.split("+git")[0]

    # some packages have alternative names, so we split CVE_PRODUCT
    for product in products_names.split():
        # CVE_PRODUCT in recipes may include vendor information for CPE identifiers. If not,
        # use wildcard for vendor.
        if ":" in product:
            vendor, product = product.split(":", 1)
        else:
            vendor = ""

        pkg = {
            "name": product,
            "version": version,
            "type": "library",
            "cpe": 'cpe:2.3:*:{}:{}:{}:*:*:*:*:*:*:*'.format(vendor or "*", product, version),
            "purl": 'pkg:generic/{}{}@{}'.format(f"{vendor}/" if vendor else '', product, version),
            "bom-ref": str(uuid.uuid4())
        }
        if vendor != "":
            pkg["group"] = vendor
        packages.append(pkg)
    return packages

def append_to_vex_vulnerabilities(d, vex, cve, sbom_serial_number, bom_ref):
    from oe.cve_check import decode_cve_status

    decoded_status = decode_cve_status(d, cve)
    if not 'mapping' in decoded_status:
        bb.debug(2, f"Could not find status mapping in {cve}")
        return

    # Currently, only "Patched" and "Ignored" status are relevant to us.
    # See https://docs.yoctoproject.org/singleindex.html#term-CVE_CHECK_STATUSMAP for possible statuses.
    if decoded_status["mapping"] == "Patched":
        bb.debug(2, f"Found patch for {cve} in {d.getVar('BPN')}")
        vex_state = "resolved"
    elif decoded_status["mapping"] == "Ignored":
        bb.debug(2, f"Found ignore statement for {cve} in {d.getVar('BPN')}")
        vex_state = "not_affected"
    else:
        bb.debug(2, f"Found unknown or irrelevant CVE status {decoded_status['mapping']} for {cve} in {d.getVer('BPN')}. Skipping...")
        return

    detail_string = ""
    if decoded_status["detail"]:
        detail_string += f"STATE: {decoded_status['detail']}\n"
    if decoded_status["description"]:
        detail_string += f"JUSTIFICATION: {decoded_status['description']}\n"
    vex["vulnerabilities"].append({
        "id": cve,
        # vex documents require a valid source, see https://github.com/DependencyTrack/dependency-track/issues/2977
        # this should always be NVD for yocto CVEs.
        "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve}"},
        "analysis": {
            "state": vex_state,
            "detail": detail_string
        },
        "affects": [{"ref": f"urn:cdx:{sbom_serial_number}/1#{bom_ref}"}]
    })
