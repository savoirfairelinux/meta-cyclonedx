# SPDX-License-Identifier: MIT
# Copyright 2022 BG Networks, Inc.
# Copyright (C) 2024 Savoir-faire Linux Inc. (<www.savoirfairelinux.com>).

# The product name that the CVE database uses.  Defaults to BPN, but may need to
# be overriden per recipe (for example tiff.bb sets CVE_PRODUCT=libtiff).
CVE_PRODUCT ??= "${BPN}"
CVE_VERSION ??= "${PV}"

CYCLONEDX_EXPORT_DIR ??= "${DEPLOY_DIR}/cyclonedx-export"
CYCLONEDX_EXPORT_SBOM ??= "${CYCLONEDX_EXPORT_DIR}/bom.json"
CYCLONEDX_EXPORT_TMP ??= "${TMPDIR}/cyclonedx-export"
CYCLONEDX_EXPORT_LOCK ??= "${CYCLONEDX_EXPORT_TMP}/bom.lock"

python do_cyclonedx_init() {
    import uuid
    from datetime import datetime

    sbom_dir = d.getVar("CYCLONEDX_EXPORT_DIR")
    bb.debug(2, "Creating cyclonedx directory: %s" % sbom_dir)
    bb.utils.mkdirhier(sbom_dir)

    bb.debug(2, "Creating empty sbom")
    write_sbom(d, {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": datetime.now().astimezone().isoformat(),
            "tools": [{"name": "yocto"}]
        },
        "components": []
    })
}
addhandler do_cyclonedx_init
do_cyclonedx_init[eventmask] = "bb.event.BuildStarted"

python do_cyclonedx_package_collect() {
    # load the bom
    name = d.getVar("CVE_PRODUCT")
    version = d.getVar("CVE_VERSION")
    sbom = read_sbom(d)

    for pkg in generate_packages_list(name, version):
        if not next((c for c in sbom["components"] if c["cpe"] == pkg["cpe"]), None):
            sbom["components"].append(pkg)

    # write it back to the deploy directory
    write_sbom(d, sbom)
}

addtask do_cyclonedx_package_collect before do_build after do_fetch
do_cyclonedx_package_collect[nostamp] = "1"
do_cyclonedx_package_collect[lockfiles] += "${CYCLONEDX_EXPORT_LOCK}"
do_rootfs[recrdeptask] += "do_cyclonedx_package_collect"

def read_sbom(d):
    import json
    from pathlib import Path
    return json.loads(Path(d.getVar("CYCLONEDX_EXPORT_SBOM")).read_text())

def write_sbom(d, sbom):
    import json
    from pathlib import Path
    Path(d.getVar("CYCLONEDX_EXPORT_SBOM")).write_text(
        json.dumps(sbom, indent=2)
    )

def generate_packages_list(products_names, version):
    """
    Get a list of products and generate CPE and PURL identifiers for each of them.
    """
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
            "purl": 'pkg:{}/{}@{}'.format(vendor or "generic", product, version)
        }
        if vendor != "":
            pkg["group"] = vendor
        packages.append(pkg)
    return packages
