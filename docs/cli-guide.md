# Command Line SBOM Generation

The CBI p2 SBOM Generator supports command-line invocation via the CBI p2 SBOM Application.
Most command-line options passed to the application are forwarded directly to the generator.
The generator options are described first, followed by a description of the application options.

## Repository Inputs

The generator allows specifying one or more [p2 repositories](overview.md#p2-repositories) as input.
These repositories are loaded and analyzed for the primary components of the SBOM.

### `-input` `<uri>`+

Specify one or more combined (metadata + artifact) p2 repository locations.
Combined (colocated) repositories are the most common case.

### `-metadata` `<uri>`+

Specify one or more metadata-only p2 repository locations.

### `-artifact` `<uri>`+

Specify one or more artifact-only p2 repository locations.


## Installation Input

The generator allows specifying an [installation](overview.md#installations) location as input.
An installation is logically both a metadata repository (the installation profile) and an artifact repository.
The generator reads the installation's configuration as well as the p2 profile to determine the relevant metadata and artifact repositories of the installation.
That is, the generator effectively converts the installation argument to equivalent p2 repository inputs.

### `-installation` `<path-or-uri>`

Specify an installation location or a URI of an installation.
The argument will be interpreted as one of the following:
- A file system path to an existing installation folder.
- A file system path to an existing installation archive, i.e., a `*.zip`, `*.tar`, or a `*.tar.gz`.
- A URI reference to an installation archive, i.e., a `*.zip`, `*.tar`, or a `*.tar.gz`.

When an archive is specified, it is automatically extracted to a file system location for further processing.
Nevertheless, the SBOM will reference the original location of the installation.


## Dependency Inputs

It is typically the case that a p2 repository is not transitively complete with respect to the requirements of its units,
that is, the repository's units have requirements that are satisfied by units from other repositories.
Because one of the more valuable aspects of an SBOM is dependency tracking,
the generator supports specifying so-called _dependency repositories_.
These can be specified in a way analogous to specifying repository inputs.

The dependency repositories are loaded just like the regular input repositories,
however, a component corresponding to a unit from a dependency repository is included in the SBOM
**if and only if** there exists a unit from an input repository that has a requirement that is satisfied **only** by a unit from a dependency repository.
As such, transitive dependencies of a component from the dependency repository are **not** automatically included in the SBOM.

### `-dependency-input` `<uri>`+

Specify one or more combined (metadata + artifact) p2 repository locations.

### `-dependency-metadata` `<uri>`+

Specify one or more metadata-only p2 repository locations.

### `-dependency-artifact` `<uri>`+

Specify one or more artifact-only p2 repository locations.

### `-use-repository-references-as-dependencies`

Specify that repository references should be used as dependency repositories.

It is often the case that a p2 metadata repository specifies a reference to one or more additional repositories that provide units that satisfy the requirements of the repository's units.
With this option, those repositories are automatically processed as dependency repositories as if the above arguments were explicitly specified.


## Originating Source Repositories

### `-p2-sources` `<uri>`+

Specify one or more p2 _source_ repositories.
A _source_ repository is one that contains artifacts that are the originating source of an artifact that is also in an input repository.
The generated SBOM contains a PURL reference to a source repository in preference over a reference to an input repository.

### `-strict-p2-source-repositories`

Specify to generate a PURL reference to an artifact repository only when the artifact is verified to be exactly the same artifact, i.e., the artifact bytes match.


## Caching

### `-cache` `<folder>`

Specify a folder used by the content cache for caching remote content.
This is used to avoid repeated transfers of remote resources.
The cache can be reused across multiple invocations of the generator to improve performance.
It's particularly useful with the `clearly-defined` option given the failure-prone server involved.


## Redirection

A redirection mapping of the form `<uri>-><uri>` specifies mapping an input URI matching the left-hand side to the URI on the right-hand side.
A redirection mapping specifies a so-called _folder mapping_ if both the left-hand side URI and the right-hand side URI end with a `/`.
In that case, any URI that matches the left-hand prefix URI is mapped to the right-hand URI along with the suffix appended.
When the redirection mapping is parsed by the command line processor,
each side is first inspected to determine if it corresponds to an existing file system path,
in which case it is converted to the corresponding `file:` URI.


### `-redirections` `<uri>-><uri>`+

Specify URI redirections to be used when generating a [PURL](overview.md#purl).
This allows generating an SBOM from local file system locations
while mapping those to appropriate remote network locations from which these resources are accessible or will be accessible.

### `-content-redirections` `<uri>-><uri>`+

Specify URI redirections used specifically by the content handler when accessing remote resources.
This is useful to redirect external URIs, i.e., network resources, to local resources or to equivalent mirrors.
For example, specifying the following folder mapping will redirect all Maven Central content to Eclipse's mirror of Maven Central:
```
-content-redirections
https://repo.maven.apache.org/maven2/->https://repo.eclipse.org/content/repositories/maven_central/
```


## Network

There are a number of options that support tuning the behavior of network access.

### `-retry` `<n>`

Specify the number of retries for failed retriable network operations.

Default taken from the system property `org.eclipse.cbi.p2repo.sbom.retry` or `5`.

### `-retry-delay` `<seconds>`

Specify the delay between retries in seconds.

Default from system property `org.eclipse.cbi.p2repo.sbom.retry.delay` or `30`.

### `-timeout` `<seconds>`

Specify the timeout in seconds for network operations.

Default from system property `org.eclipse.cbi.p2repo.sbom.timeout` or `30`.

## Analysis

There are a number of options that control the analysis behavior of the generator.

### `-verbose`

Specify more verbose logging to stdout/stderr; for example, print more diagnostics such as mapping problems, rejected license URLs, and so on.

### `-process-bundle-classpath`

Specify to inspect the OSGi bundle classpath entries of each bundle to extract nested JARs
and then to create subcomponents in the SBOM for those nested artifacts.

### `-central-search`

Specify to query Maven Central to attempt to map artifacts to Maven coordinates.
This helps produce canonical Maven PURLs when applicable.

### `-git-issues`

Specify to detect the issues page of GitHub repositories recognized from `SCM` details in POMs and from manifest entries `Bundle-SCM` or `Eclipse-SourceReferences`
and to generate issue-tracker external references when a corresponding GitHub issues page exists.

### `-advisory`

Specify to query the [OSV API](https://google.github.io/osv.dev/post-v1-query/) (Open Source Vulnerabilities) for vulnerabilities for components that have Maven PURLs
and add any advisory or external references found by such queries.

### `-clearly-defined`

Specify to query [ClearlyDefined](https://clearlydefined.io/) metadata for Maven coordinates to add declared license information as a component property.
The server is notoriously prone to network failure.

### `-dependency-track`

Specify to transform the generated SBOM to produce results more appropriate for uploading to 
[`dependency-track`](https://dependencytrack.org/).

A `dependency-track` server currently flattens nested components and loses pedigree details:

- [DependencyTrack#4119](https://github.com/DependencyTrack/dependency-track/issues/4119)

As a result, the useful content generated for [pedigree](overview.md#pedigree) and [nested jars](overview.md#nested-jars) is not useful for `dependency-track`.

With this option,
nested-jar components and pedigree components are flattened by the generator
and a dependency is added from the container component to the flattened component.


### `-minimize-root-dependencies`

Specify to minimize the dependencies of the SBOM's metadata component to be the roots of the dependency graph induced by all of the SBOM's components.
By default, the SBOM's metadata component depends directly on all components of the SBOM.


## Component Filters

In some cases, it can be useful to exclude components from an SBOM,
or to include only a slice or subset of the available components.
For example,
for [dependency-track](https://dependencytrack.org/)
only [bundle components](overview.md#bundle-mapping) are of general tracking interest
and even for bundle components,
the source bundle components are not of particular interest in terms of dependency tracking,
typically doubling the number of components being tracked without substantial additional value.

### `-classifier-exclusions` `<classifier>`+

Specify to exclude from the SBOM components based on component classifier.
Two common short names are recognized and mapped appropriately:
- `feature` &rarr; `org.eclipse.update.feature`
- `bundle` &rarr; `osgi.bundle`

### `-component-exclusions` `<pattern>`

Specify a regular-expression pattern to match names of components to be excluded from the SBOM.
For example, specifying `.*\.source` can be used to exclude all source bundles.

### `-expected-missing-artifact-iu-patterns` `<pattern>`+

Specify one or more regular expressions that will be applied to the `<component-name>:<component-version>` of any component that is determined to be missing a corresponding artifact
to suppress the generation of a `missing-artifact` property on that component.

There are some exceptional situations where [p2 metadata customizations](https://eclipse.dev/eclipse/markdown/?file=eclipse-equinox/p2/master/docs/Customizing_Metadata.md)
produce metadata that would normally suggest a corresponding artifact must exist, but in fact the unit is purely metadata.
For example, the current [SimRel](https://eclipse.dev/simel) repository contains _fake_ source features and can use the following to suppress the `missing-artifact` property.
```
-expected-missing-artifact-iu-patterns
org\.eclipse\.(help|jdt|pde|pde\.spies|platform|rcp)\.source\.feature\.group:.*
```

### `-slice` `<pattern>`+

Specify one or more regular expressions that will be applied  to match,
i.e., select, the names of the so-called root components.
The transitive closure of the dependencies of the selected components will be included in the SBOM.
In other words, only a slice of all available components will be included in the SBOM.


## Dependency Filters

When mapping [requirements onto dependencies](overview.md#dependencies),
missing (unresolved) requirements are marked with an `unsatisfied-requirement` property.
This is generally undesirable because it may reflect important missing dependency information.
However, a requirement can specify a filter and is applicable only if the filter matches.
The generator allows specifying options for handling missing requirements gracefully.

### `-requirement-inclusions` `<context-spec>`+

Specify one or more inclusive context units used when evaluating requirement filters for missing requirements.
A `context-spec` is of the form `<key_1>=<value_1>{,<key_2>=<value_2>}*`,
i.e., a comma-separated list of key-value pairs.
If any inclusive units are specified,
a missing requirement will be considered relevant only if at least one of the inclusive context units matches the filter.

When a product is generated for just a small subset of the available os/win/arch combinations,
it is generally more concise to specify the supported ones than to list all the unsupported ones.

### `-requirement-exclusions` `<context-spec>`+

Specify one or more context units used when evaluating requirement filters for missing requirements.
The format is the same as for `requirement-inclusions`.
If any exclusive units are specified,
a missing requirement will be considered irrelevant if any one of the exclusive context units matches the filter.

When a product is generated for most of the available os/win/arch combinations,
it is generally more concise to specify the unsupported ones than to list all the supported ones.

## Output

Given the purpose of the SBOM generator is to generate an SBOM,
a command-line invocation will generally specify the type of SBOM and the location of the SBOM.

### `-xml`

Specify to print the CycloneDX SBOM XML to stdout.

### `-json`

Specify to print the CycloneDX SBOM JSON to stdout.

### `-xml-output` `<file>`

Specify to write the CycloneDX SBOM XML to the given file.

### `-json-output` `<file>`

Specify to write the CycloneDX SBOM JSON to the given file.

---

## Multiple Installation or Slice Generation

The CBI p2 SBOM Generator Application provides a wrapper around the CBI p2 SBOM Generator.
It provides support for generating an HTML index with links to the SBOM as well as links to the renderer for those SBOMs.
In addition, it provides support for generating SBOMs for a folder containing multiple product (installation) archives.

### `-installations` `<folder>`

Specifies a folder containing product archives, i.e., `*.zip`, `*.tar`, or `*.tar.gz`.

The SBOM generator will be invoked separately for each installation.
<a href="#-installation-path-or-uri">See `-installation`</a>.

### `-installation-pattern` `<pattern>`

Specify the pattern for installation archives.
The default when no pattern is specified is `.*\.(zip|tar|tar.gz)$`

### `-slices` `<slice-spec>`+

Specifies one or more `<slice-specs>` instances of the form `<name>=<pattern>`.

The SBOM generator will be invoked separately for each slice.
<a href="#-slice-pattern">See `-slice`</a>.


### `-xml-outputs` `<folder>`

Specify the folder in which to generate an XML SBOM for each installation.

### `-json-outputs` `<folder>`

Specify the folder in which to generate a JSON SBOM for each installation.

### Multiple Invocation Mode

#### Multiple Installations

For each matching installation `<installation-path>` in the `-installations` folder, the following processing is invoked:
- The effective arguments for the p2 SBOM generator invocation are a copy of the application arguments with the application-specific arguments removed.
- The invocation specifies `-installation` `<installation-path>` to generate an SBOM for that installation.
- If `-xml-outputs` `<folder>` is specified, the invocation specifies `-xml-output` `<folder>/<installation-base-name>-sbom.xml`.
- If `-json-outputs` `<folder>` is specified, the invocation specifies `-json-output` `<folder>/<installation-base-name>-sbom.json`.

#### Multiple Slices

For each `<slice-spec>` of the form `<name>=<pattern>` in the `-slices`, the following processing is invoked:
- The effective arguments for the p2 SBOM generator invocation are a copy of the application arguments with the application-specific arguments removed.
- The invocation specifies `-slice` `<pattern>` to generate an SBOM for that slice; note that `|` can be used to specify multiple patterns as a single pattern.
- If `-xml-outputs` `<folder>` is specified, the invocation specifies `-xml-output` `<folder>/<name>-sbom.xml`.
- If `-json-outputs` `<folder>` is specified, the invocation specifies `-json-output` `<folder>/<name>-sbom.json`.

### Single Invocation Mode

If neither `-installations` nor `-slices` are specified,
the p2 SBOM generator is invoked with a copy of the application arguments.
In this case, the caller is expected to have provided `-installation`, `-inputs`, or other input arguments,
as well as specific [output arguments](#output).


### Index and Rendering

#### `-index` `<file>`

Specify generating an HTML index file at the specified file path that details the generated SBOMs.

#### `-renderer` `<uri>`

Specify the renderer base URL to be used for producing renderer links in the index.
Defaults to [https://download.eclipse.org/cbi/sbom](https://download.eclipse.org/cbi/sbom).
Due to cross-origin scripting restrictions, the referenced SBOM URI and the renderer URI must be hosted by the same origin.


#### `-preview` `<uri>-><uri>`

Specify a [URI redirection](#redirection) to redirect the `-index` location URI to the URI where it is or will be hosted.
Due to cross-origin scripting restrictions, the referenced SBOM URI and the renderer URI must be hosted by the same origin.

This mapping is parsed and used to possibly open the generated index in a browser (if the redirected index URL is not a file: scheme).

#### Index and Rendering Example

In the [CBI p2 SBOM Development IDE](../CONTRIBUTING.md)
we use the following in launch configurations in order to open the renderer via `localhost` in a browser:

```
-index
${project_loc:/samples}/index.html
-renderer
http://localhost:${localhost.port}/sbom
-preview
${system_property:user.home}->http://localhost:${localhost.port}/user.home/
```
