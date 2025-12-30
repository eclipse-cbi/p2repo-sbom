# CBI p2 SBOM Generator

The CBI p2 SBOM Generator supports generating a high-quality Software Bill of Materials from a p2 repository or an Eclipse installation.
The generator provides the following:
- A headless product that supports a command-line interface.
- IDE integration to drive the generation process from within the IDE.

The project also supports a [web-based renderer](https://download.eclipse.org/cbi/sbom/) to provide a user-friendly overview of an SBOM's overwhelmingly large volume of textual content.

## Conceptual Overview

It is highly recommended to read the [conceptual overview](overview.md) for a deeper understanding of the concepts involved.

## Command Line Interface

Please read the [command-line interface](cli-guide.md) guide for details about the supported command line options.

## Maven/Jenkins Integration

Please read the [Maven/Jenkins Integration](build-guide.md) guide for details about driving the generation process in continuous integration builds.

## IDE Integration

Please read the [IDE guide](ide-guide.md) for details about the IDE integration.

## Web-based Renderer

Please read the [renderer guide](renderer-guide.md) for details about the web-based renderer.

## Setting Up a Development Environment

You can set up a pre-configured IDE for the development of the p2 SBOM Generator projects using the following link.

[![Create Eclipse Development Environment for the p2 SBOM Generator](https://download.eclipse.org/oomph/www/setups/svg/p2_SBOM.svg)](https://www.eclipse.org/setups/installer/?url=https://raw.githubusercontent.com/eclipse-cbi/p2repo-sbom/main/releng/org.eclipse.cbi.p2repo.sbom.releng.parent/setup/P2RepositorySBOMConfiguration.setup&show=true "Click to open Eclipse-Installer Auto Launch or drag onto your running installer's title area")

## Continuous Integration

The following job builds the headless product and the update sites:

- https://ci.eclipse.org/cbi/view/p2RepoRelated/job/p2repo-sbom/

The website is kept up-to-date via the following job:

- https://ci.eclipse.org/cbi/view/p2RepoRelated/job/cbi.p2repo.sbom-promote-website/

## Acknowledgement

[YourKit](https://www.yourkit.com/) is kindly supporting open source projects with its full-featured YourKit Java Profiler.
YourKit, LLC is the creator of innovative and intelligent tools for profiling Java and .NET applications.

With the help of the YourKit Java Profiler,
the performance of the CBI p2 SBOM Generator is significantly improved.
