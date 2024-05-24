# meta-cyclonedx

`meta-cyclonedx` is a [Yocto](https://www.yoctoproject.org/) meta-layer which produces a [CycloneDX](https://cyclonedx.org/) Software Bill of Materials (aka [SBOM](https://www.ntia.gov/SBOM)) from your root filesystem.  
This repository is forked from [BG Networks repository](https://github.com/bgnetworks/meta-dependencytrack) but differs by the following:
- Removed support for DependencyTrack.
- Exported CycloneDX include packages, but also vulnerabilities found by Yocto.
- generation of CPE is fixed and also generate purl for packages.

## Installation

To install this meta-layer simply clone the repository into the `sources` directory and add it to your `build/conf/bblayers.conf` file:

```sh
$ cd sources
$ git clone https://github.com/savoirfairelinux/meta-cyclonedx.git
```

and in your `bblayers.conf` file:

```sh
BBLAYERS += "${BSPDIR}/sources/meta-cyclonedx"
```

## Configuration

To enable and configure the layer simply inherit the `cyclonedx-export` class in your `local.conf` file and then set the following variables:

### Example

```sh
INHERIT += "cyclonedx-export"
```

## Building and Uploading

Once everything is configured simply build your image as you normally would. The final CycloneDX SBOM is saved as `tmp/deploy/cyclonedx-export/bom.json` and, after buiding is complete, you should be able to simply refresh the project in Dependency Track to see the results of the scan.
