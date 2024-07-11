# meta-cyclonedx

`meta-cyclonedx` is a [Yocto](https://www.yoctoproject.org/) meta-layer which produces [CycloneDX](https://cyclonedx.org/) Software Bill of Materials (aka [SBOM](https://www.ntia.gov/SBOM)) from your root filesystem.

This repository is forked from [BG Networks repository](https://github.com/bgnetworks/meta-dependencytrack) but differs by the following:
- Removed direct integration with DependencyTrack.
- Exported CycloneDX include packages, but also vulnerabilities found by Yocto.
- Generation of CPE is fixed and also generate purl for packages.
- Added generation of an additional CycloneDX VEX file which contains information on patched and ignored CVEs from within the Yocto Build System.

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

To enable and configure the layer simply inherit the `cyclonedx-export` class in your `local.conf` file and then set the following variable:

```sh
INHERIT += "cyclonedx-export"
```

## Building

Once everything is configured simply build your image as you normally would.

Alternatively, if you are only interested in the CycloneDX files, you may append your bitbake command with `--runonly=do_cyclonedx_package_collect` which will limit bitbake to run only the required tasks for creating the CycloneDX output.

By default the final CycloneDX SBOMs are saved in the folder `${DEPLOY_DIR}/cyclonedx-export` as `bom.json` and `vex.json` respectively.

## Uploading to DependencyTrack (tested against DT v4.11.4)

While this layer does not offer a direct integration with DependencyTrack (we consider that a feature, since it removes dependencies to external infrastructure in your build), it is perfectly possible to use the produced SBOMs within DependencyTrack.

At the time of writing DependencyTrack does not support uploading component and vulnerability information in one go (which is why we currently create two separate files). The status on this may be tracked [here](https://github.com/DependencyTrack/dependency-track/issues/919).

### Manual Upload

1. Go into an existing project in your DependencyTrack instance or create a new one.
2. Go to the *Components* tab and click *Upload BOM*.
3. Select the `bom.json` file from your deploy directory.
4. Wait for the vulnerability analysis to complete.
5. Go to the *Audit Vulnerabilities* tab and click *Apply VEX*.
6. Select the `vex.json` file from your deploy directory.

### Automated Upload

You may want to script the upload of the SBOMs to DependencyTrack, e.g. as part of a CI job that runs after your build is complete.

This is possible by leveraging DependencyTracks REST API.

At the time of writing this can be done by leveraging the following API endpoints:

1. `/v1/bom` for uploading the `bom.json`.
2. `/v1/event/token/{uuid}` for checking the status on the `bom.json` processing.
3. `/v1/vex` for uploading the `vex.json`.

Please refer to [DependencyTracks REST API documentation](https://docs.dependencytrack.org/integrations/rest-api/) for the usage of these endpoints as well as the required token permissions.

In the future we might include an example script in this repository.
