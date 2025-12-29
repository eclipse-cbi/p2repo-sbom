# CBI p2 SBOM Conceptual Overview

An Eclipse application based on the 
[Eclipse Platform](https://eclipse.dev/eclipse/)
is an
[OSGi](https://docs.osgi.org/)
application composed from
[bundles](https://docs.osgi.org/specification/osgi.core/8.0.0/framework.module.html#d0e2803)
as the primary building blocks.
The Platform's OSGi implementation,
[Equinox](https://github.com/eclipse-equinox/),
supports a provisioning framework
[p2](https://help.eclipse.org/latest/index.jsp?topic=%2Forg.eclipse.platform.doc.isv%2Fguide%2Fp2_api_overview.htm)
for managing p2 repositories that provide access to the application units,
e.g., the application bundles,
for provisioning application installations from those units.

A Software Bill of Materials (SBOM),
is a formal inventory of a software application's components,
including metadata about those components as well as dependencies between those components.
To produce an SBOM for an Eclipse application,
the building blocks of the application must be mapped onto a formal SBOM model.
The CBI p2 SBOM generator uses 
[CycloneDX](https://cyclonedx.org/)
as the formal representation,
currently the specification version
[1.6](https://cyclonedx.org/specification/overview/).

OSGi provides rich metadata for each bundle,
e.g.,
bundle symbolic name,
bundle version,
and so on.
In terms of dependencies,
each bundle declares its provided
[capabilities](https://docs.osgi.org/specification/osgi.core/8.0.0/framework.module.html#d0e2870)
and specifies
[requirements](https://docs.osgi.org/specification/osgi.core/8.0.0/framework.module.html#d0e3015)
relative to such capabilities.
The p2 framework provides analogous concepts,
projecting the OSGi metadata as p2 metadata.
This information is a rich source of details from which to derive an SBOM.
That being said,
there is a significant impedance mismatch between the concept of OSGi/p2 requirements versus the concept of
[SBOM dependencies](https://cyclonedx.org/docs/1.6/json/#dependencies).


## Application Units

An Eclipse application comprises additional building blocks
as supported by the Eclipse Plug-in Development Environment,
[PDE](https://projects.eclipse.org/projects/eclipse.pde):
- A [plug-in](https://help.eclipse.org/latest/index.jsp?topic=%2Forg.eclipse.pde.doc.user%2Fconcepts%2Fplugin.htm)
  is effectively just a synonym for a bundle.
- A [fragment](https://help.eclipse.org/latest/index.jsp?topic=%2Forg.eclipse.pde.doc.user%2Fconcepts%2Ffragment.htm&cp%3D4_1_2)
  is a special type of bundle that extends a so-called host bundle, typically with a platform-native implementation.
- A [feature](https://help.eclipse.org/latest/index.jsp?topic=%2Forg.eclipse.pde.doc.user%2Fconcepts%2Ffeature.htm&cp%3D4_1_1)
  is a collection of dependencies on plug-ins, fragments, and other features.
  It is intended as a user-facing unit that provides support for some high-level functionality that the user may choose to install in an application.
- A [product](https://help.eclipse.org/latest/index.jsp?topic=%2Forg.eclipse.pde.doc.user%2Fconcepts%2Fproduct.htm&cp%3D4_1_4)
  is a description of a complete stand-alone Eclipse application,
  specifying the bundles, fragments, and features to be installed, program arguments, JVM arguments, branding details, and so on.
All these building blocks are mapped onto p2 and made available via p2 repositories.

## p2 Repositories

The p2 framework supports two types of repository, often colocated at the same URL:
- Metadata 
  - This provides access to
    [installable units](https://eclipse.dev/eclipse/markdown/?file=eclipse-equinox/p2master/docs/Installable_Units.md)
    which specify metadata about all the units available for provisioning an application,
    including the unit's provided capabilities as well as its required capabilities.
    Each installable unit is uniquely identified by its ID and version.
- Artifact 
  - This provides access to the actual physical artifacts, e.g., jars and binaries.
    Each artifact is uniquely identified by its artifact key,
    i.e., its classifier, ID, and version.

### p2 Engine

When an application is installed or updated by the p2 engine,
a request to add, remove, or update installable units is specified,
and one or more metadata repositories are made available to satisfy that request.
The engine builds a so-called plan using
[sat4j](https://www.sat4j.org/)
and then executes that plan.

An installable unit typically, but not always, has an associated artifact specified by an artifact key.
For the engine to execute the plan,
one or more artifact repositories providing access to the corresponding artifact of each installable unit in the plan must be made available.
An installable unit can also specify touchpoints,
i.e., instructions for how to process the specified artifact,
or even instructions for how to modify the target installation.

### Installations

The building blocks that comprise an Eclipse product installation,
as provisioned by p2,
are defined by the following:
- A profile that specifies the installable units of the installation, which is logically a p2 metadata repository.
- An artifact repository that specifies the location of each corresponding artifact of each installable unit in that installation.

In this sense,
an installation is logically equivalent to a pair of p2 repositories.
The CBI p2 SBOM generator exploits this equivalence,
making it possible to generate an SBOM for p2 repositories and for Eclipse installations with the same underlying implementation logic.

## SBOM Component Mapping

Given the typical close correspondence between installable unit and artifact,
and given SBOM's primary focus on components as artifacts,
it is beneficial to unify these two aspects during the process of mapping p2 units and artifacts onto SBOM components.
The components of a generated SBOM are mapped as follows:

### Bundle Mapping

A bundle unit is a component of type [library](https://cyclonedx.org/docs/1.6/json/#components_items_type).
It corresponds to both an installable unit and that unit's associated artifact.
```xml
<unit id='org.example.abc' version='1.1.0.v20250601-0000' generation='2'>
  <update id='org.example.abc' range='[0.0.0,1.1.0.v20250601-0000)' severity='0'/>
  <provides size='10'>
    <provided namespace='org.example.abc.p2.iu' name='org.example.abc' version='1.1.0.v20250601-0000'/>
    <provided namespace='osgi.bundle' name='org.example.abc' version='1.1.0.v20250601-0000'/>
    <provided namespace='osgi.identity' name='org.example.abc' version='1.1.0.v20250601-0000'>
      <properties size='1'>
        <property name='type' value='osgi.bundle'/>
      </properties>
    </provided>
    <provided namespace='org.eclipse.equinox.p2.eclipse.type' name='bundle' version='1.0.0'/>
  </provides>
  <artifacts size='1'>
    <artifact classifier='osgi.bundle' id='org.example.abc' version='1.1.0.v20250601-0000'/>
  </artifacts>
</unit>
```
The artifact is a jar representing an OSGi bundle.
The jar may be unpacked when provisioned into an installation.

The ID of the unit is mapped to the [name](https://cyclonedx.org/docs/1.6/json/#components_items_name) of the component.
The version of the unit is mapped to the [version](https://cyclonedx.org/docs/1.6/json/#components_items_version) of the component.
The [scope](https://cyclonedx.org/docs/1.6/json/#components_items_scope) is set to required, which is the implicit default.
The [bom-ref](https://cyclonedx.org/docs/1.6/json/#components_items_bom-ref) is set to `plugins/<ID>_<version>.jar`,
i.e., analogous to the mapping of the artifact in the artifact repository.


### Feature Mapping

A feature unit is a component of type [library](https://cyclonedx.org/docs/1.6/json/#components_items_type).
It corresponds to a pair of installable units, `*.feature.group` and `*.feature.jar`,
where `*` is the base ID,
as well as the units' associated artifact ID.
```xml
<unit id='org.example.abc.feature.group' version='1.0.0.v20250601-000' singleton='false'>
  <update id='org.example.abc.feature.group' range='[0.0.0,1.0.0.v20250601-000)' severity='0'/>
  <provides size='2'>
    <provided namespace='org.eclipse.equinox.p2.iu' name='org.example.abc.feature.group' 
        version='1.0.0.v20250601-000'/>
  </provides>
  <requires size='2'
    <required namespace='org.eclipse.equinox.p2.iu' name='org.example.abc'
        range='[1.0.0.v20250601-000,1.0.0.v20250601-000]'/>
    <required namespace='org.eclipse.equinox.p2.iu' name='org.example.abc.feature.jar'
        range='[1.0.0.v20250601-000,1.0.0.v20250601-000]'>
      <filter>
        (org.eclipse.update.install.features=true)
      </filter>
    </required>
  </requires>
</unit>
<unit id='org.example.abc.feature.jar' version='1.0.0.v20250601-000'>
  <provides size='3'>
    <provided namespace='org.eclipse.equinox.p2.iu' name='org.example.abc.feature.jar'
        version='1.0.0.v20250601-000'/>
    <provided namespace='org.eclipse.equinox.p2.eclipse.type' name='feature' version='1.0.0'/>
    <provided namespace='org.eclipse.update.feature' name='org.example.abc' version='1.0.0.v20250601-000'/>
  </provides>
  <filter>
    (org.eclipse.update.install.features=true)
  </filter>
  <artifacts size='1'>
    <artifact classifier='org.eclipse.update.feature' id='org.example.abc' version='1.0.0.v20250601-000'/>
  </artifacts>
  <touchpoint id='org.eclipse.equinox.p2.osgi' version='1.0.0'/>
  <touchpointData size='1'>
    <instructions size='1'>
      <instruction key='zipped'>
        true
      </instruction>
    </instructions>
  </touchpointData>
</unit>
```
It is a jar representing an Eclipse feature.
The jar effectively just contains the `feature.xml` and therefore contributes no behavior to an actual running application.
The feature jar will be unpacked when provisioned into an installation.

The ID of the `*.feature.jar` unit is mapped to the [name](https://cyclonedx.org/docs/1.6/json/#components_items_name) of the component.
The common version of the units is mapped to the [version](https://cyclonedx.org/docs/1.6/json/#components_items_version) of the component.
The [scope](https://cyclonedx.org/docs/1.6/json/#components_items_scope) is set to required, which is the implicit default.
The [bom-ref](https://cyclonedx.org/docs/1.6/json/#components_items_bom-ref) is set to `features/<base-ID>_<version>.jar`,
i.e., analogous to the mapping of the artifact in an artifact repository.


### Binary Mapping

A binary unit is a component of type [library](https://cyclonedx.org/docs/1.6/json/#components_items_type).
It corresponds to both an installable unit and that unit's associated artifact.
```xml
<unit id='org.example.abc.executable_root.gtk.linux.x86_64' version='1.0.0.v20250601-000'>
  <provides size='1'>
    <provided namespace='org.eclipse.equinox.p2.iu' name='org.example.abc.executable_root.gtk.linux.x86_64'
        version='1.0.0.v20250601-000'/>
  </provides>
  <filter>
    (&amp;(osgi.arch=x86_64)(osgi.os=linux)(osgi.ws=gtk))
  </filter>
  <artifacts size='1'>
    <artifact classifier='binary' id='org.example.abc.executable_root.gtk.linux.x86_64'
        version='1.0.0.v20250601-000'/>
  </artifacts>
  <touchpoint id='org.eclipse.equinox.p2.native' version='1.0.0'/>
  <touchpointData size='2'>
    <instructions size='2'>
      <instruction key='uninstall'>
        cleanupzip(source:@artifact, target:${installFolder});
      </instruction>
      <instruction key='install'>
        unzip(source:@artifact, target:${installFolder});
      </instruction>
    </instructions>
    <instructions size='1'>
      <instruction key='install'>
        chmod(targetDir:${installFolder}, targetFile:launcher, permissions:755);
      </instruction>
    </instructions>
  </touchpointData>
</unit>
```
It is generally a zip file
whose contents are processed by so-called touchpoints to provision artifacts into an installation.
For example,
it can contain a native executable
that will be assigned the appropriate POSIX permissions when placed at its intended destination.

The ID of the unit is mapped to the [name](https://cyclonedx.org/docs/1.6/json/#components_items_name) of the component.
The version of the unit is mapped to the [version](https://cyclonedx.org/docs/1.6/json/#components_items_version) of the component.
The [scope](https://cyclonedx.org/docs/1.6/json/#components_items_scope) is set to required, which is the implicit default.
The [bom-ref](https://cyclonedx.org/docs/1.6/json/#components_items_bom-ref) is set to `binary/<ID>_<version>`,
i.e., analogous to the mapping of the artifact in the artifact repository.


### Metadata Mapping

A metadata unit is a component of type [data](https://cyclonedx.org/docs/1.6/json/#components_items_type).
It is a logical component for which no corresponding physical artifact exists.
```xml
<unit id='toolingorg.example.abc.ini.gtk.linux.x86_64' version='1.0.0.v20250601-000' singleton='false'>
  <provides size='2'>
    <provided namespace='org.eclipse.equinox.p2.iu' name='toolingorg.example.abc.ini.gtk.linux.x86_64'
        version='1.0.0.v20250601-000'/>
    <provided namespace='toolingorg.example.abc' name='epp.package.committers.ini' version='1.0.0.v20250601-000'/>
  </provides>
  <filter>
    (&amp;(osgi.arch=x86_64)(osgi.os=linux)(osgi.ws=gtk))
  </filter>
  <touchpoint id='org.eclipse.equinox.p2.osgi' version='1.0.0'/>
  <touchpointData>
    <instructions>
      <instruction key='unconfigure'>
        removeJvmArg(jvmArg:-Dosgi.requiredJavaVersion=21);
        removeJvmArg(jvmArg:-Dosgi.instance.area.default=@user.home/eclipse-workspace);
        removeJvmArg(jvmArg:-Dosgi.dataAreaRequiresExplicitInit=true);
        removeJvmArg(jvmArg:-Dorg.eclipse.swt.graphics.Resource.reportNonDisposed=true);
        removeJvmArg(jvmArg:-Declipse.e4.inject.javax.warning=false);
        removeJvmArg(jvmArg:-Dorg.slf4j.simpleLogger.defaultLogLevel=off);
        removeJvmArg(jvmArg:-Dsun.java.command=Eclipse);
        removeJvmArg(jvmArg:-XX${#58}+UseG1GC);
        removeJvmArg(jvmArg:-XX${#58}+UseStringDeduplication);
        removeJvmArg(jvmArg:--add-modules=ALL-SYSTEM);
        removeProgramArg(programArg:-product);
        removeProgramArg(programArg:org.eclipse.epp.package.committers.product);
        removeProgramArg(programArg:-showsplash);
        removeProgramArg(programArg:org.eclipse.epp.package.common);
        removeProgramArg(programArg:--launcher.defaultAction);
        removeProgramArg(programArg:openFile);
        removeProgramArg(programArg:--launcher.appendVmargs);
      </instruction>
      <instruction key='configure'>
        addJvmArg(jvmArg:-Dosgi.requiredJavaVersion=21);
        addJvmArg(jvmArg:-Dosgi.instance.area.default=@user.home/eclipse-workspace);
        addJvmArg(jvmArg:-Dosgi.dataAreaRequiresExplicitInit=true);
        addJvmArg(jvmArg:-Dorg.eclipse.swt.graphics.Resource.reportNonDisposed=true);
        addJvmArg(jvmArg:-Declipse.e4.inject.javax.warning=false);
        addJvmArg(jvmArg:-Dorg.slf4j.simpleLogger.defaultLogLevel=off);
        addJvmArg(jvmArg:-Dsun.java.command=Eclipse);
        addJvmArg(jvmArg:-XX${#58}+UseG1GC);
        addJvmArg(jvmArg:-XX${#58}+UseStringDeduplication);
        addJvmArg(jvmArg:--add-modules=ALL-SYSTEM);
        addProgramArg(programArg:-product);
        addProgramArg(programArg:org.eclipse.epp.package.committers.product);
        addProgramArg(programArg:-showsplash);
        addProgramArg(programArg:org.eclipse.epp.package.common);
        addProgramArg(programArg:--launcher.defaultAction);
        addProgramArg(programArg:openFile);
        addProgramArg(programArg:--launcher.appendVmargs);
      </instruction>
    </instructions>
  </touchpointData></unit>
```
It exists only in a p2 metadata repository or in an installation profile,
which is also logically a metadata p2 repository.
It can specify dependencies on other components
as well as touchpoints describing actions to be applied to artifacts as they are installed.
It contributes no behavior to an actual running application,
but rather provides for the management of the configuration of that application.

The ID of the unit is mapped to the [name](https://cyclonedx.org/docs/1.6/json/#components_items_name) of the component.
The version of the unit is mapped to the [version](https://cyclonedx.org/docs/1.6/json/#components_items_version) of the component.
The [scope](https://cyclonedx.org/docs/1.6/json/#components_items_scope) is set to required, which is the implicit default.
The [bom-ref](https://cyclonedx.org/docs/1.6/json/#components_items_bom-ref) is set to `metadata/<ID>_<version>`.

### Unit Properties

The units of a metadata repository and artifact repository can specify additional named properties,
i.e., key-value pairs,
associated with that unit.
Many of these are of interest when mapping a unit to a component.
For example, a unit can specify the provider, the name, and a description,
all of which are user-facing information about the unit.
The provider of a unit, if specified,
is mapped to the [publisher](https://cyclonedx.org/docs/1.6/json/#components_items_publisher) of the component.
The name and the description, if specified, are combined
and are mapped to the [description](https://cyclonedx.org/docs/1.6/json/#components_items_description) of the component.

The properties can also specify details,
e.g., the Maven coordinates of the unit,
that are used for other aspects of the component mapping process.
Some properties may even be mapped directly to [properties](https://cyclonedx.org/docs/1.6/json/#components_items_properties) of the component;
this is the case only for properties that are not otherwise mapped
or are not recognized to be of direct interest.

### PURL

A package URL specifies a [standardized identity](https://github.com/package-url/purl-spec) for each mapped component.
Many of the artifacts (bundles) used by Eclipse applications originate from Maven Central.
These can be identified by so-called `maven` type PURL as follows:
```
pkg:maven/<groupId>/<artifactId>@<version>
```
Other artifacts are available purely from a p2 repository.
These can be identified using the [proposed](https://github.com/package-url/purl-spec/issues/271) `p2` type PURL as follows:
```
pkg:p2/<id>@<version>?classifier=<unit-classifier>&repository_url=<repository-uri>
```
The mapping process of the CBI p2 SBOM generator specifies mappings for both metadata units and artifact units,
with a primary focus on the artifacts.
The generator associates a PURL with every mapped component.
As mentioned previously,
the unit properties often provide traceability detail such as the Maven coordinates of the artifact.
If those are available,
**and** the generator can confirm that the local artifact is indeed byte-for-byte identical to the artifact on Maven Central,
a `maven` type PURL is associated with the component.
Otherwise a `p2` type PURL is associated with the component where
a bundle unit's classifier is `osgi.bundle`,
a feature unit's classifier is `org.eclipse.update.feature`,
a binary unit's classifier is `binary`,
and a metadata unit's classifier is `metadata`.
While metadata and artifact repositories are typically colocated,
that's not always the case
and for application installations,
it's never the case.
The `repository-uri` is generally the artifact repository URI,
except for metadata units for which it is the metadata repository URI.

### Pedigree 

Special care must be taken when associating a `maven` type PURL with an artifact.
In particular,
the SBOM consumer must be guaranteed that the hash sum of an artifact is in fact identical to the hash sum of the originating artifact on Maven Central.
There are a number of reasons why this might not be the case,
for example,
BND instructions may be used to synthesize an OSGi-compatible `MANIFEST.MF` for the jar,
thereby modifying the artifact.

If a unit specifies Maven coordinates,
**and** an artifact exists for that coordinate **but** the artifact is not byte-for-byte identical,
a `p2` type PURL is associated with the component.
In addition,
a [pedigree](https://cyclonedx.org/docs/1.6/json/#components_items_pedigree) is also associated with the component.
The pedigree specifies the original Maven coordinates via the [ancestors](https://cyclonedx.org/docs/1.6/json/#components_items_pedigree_ancestors).
I.e.,
the ancestor is a nested component that specifies
the `groupId` as the [group](https://cyclonedx.org/docs/1.6/json/#components_items_group),
the `artifactId` as the [name](https://cyclonedx.org/docs/1.6/json/#components_items_name),
the `version` as the [version](https://cyclonedx.org/docs/1.6/json/#components_items_version),
and the `maven` type PURL as the [purl](https://cyclonedx.org/docs/1.6/json/#components_items_purl).

### Nested Jars

An OSGi bundle may specify a
[bundle classpath](https://docs.osgi.org/specification/osgi.core/8.0.0/framework.module.html#framework.module.bundleclasspath)
that references jars nested within the bundle.
These jars are often Maven artifacts or derived from Maven artifacts.
In all cases,
each such jar is mapped to a [nested component](https://cyclonedx.org/docs/1.6/json/#components_items_components).

The CBI p2 SBOM generator scans for such jars on the bundle classpath, and attempts to determine the corresponding Maven artifact:
- It looks for POM details in the jar or adjacent to the jar to determine the Maven coordinates.
- It queries Maven Central for the SHA-1 of the jar.
- It queries Maven Central based on the `artifactId`, `version`, and optional `classifier` as determined by the name of the jar.

Based on a successful query result,
the generator will verify that the corresponding Maven artifact exists and is byte-for-byte equal to the nested jar.
If the Maven artifact is byte-for-byte equal,
a Maven-type [PURL](#purl)
is associated with the nested jar component.
Otherwise, if the Maven artifact exists but is modified in some way,
a [pedigree](#pedigree)
is associated with the nested jar component.

### Hashes

[Hash sums](https://cyclonedx.org/docs/1.6/json/#components_items_hashes_items_content) are computed for each mapped component with an associated artifact
using the [algorithms](https://cyclonedx.org/docs/1.6/json/#components_items_hashes_items_alg)
`MD5`, `SHA-1`, `SHA-256`, `SHA-512`, `SHA-384` and `SHA3-256`.
Hash sums are not computed for [metadata](#metadata-mapping) units.
As mentioned previously,
artifacts may be unpacked when installed.
The p2 framework will automatically zip such artifacts as needed for an artifact request.
The resulting artifact is generally not byte-for-byte identical to the original artifact in the originating p2 repository
and will therefore have different hash sums.

### Licenses

[Licenses](https://cyclonedx.org/docs/1.6/json/#components_items_licenses) are computed on an ad hoc basis for each mapped component.
There are **many** available sources of potential license information.
- The p2 license metadata.
- The OSGi `MANIFEST.MF` `Bundle-License` header.
- The `license` element in a POM.
- Various embedded license documents in the artifact, e.g., `about.html`.

Often this information is recorded in a poorly standardized way, making reliable extraction by the CBI p2 SBOM generator an ongoing challenge.

### Details

As described in the [Unit Properties](#unit-properties) section,
the [publisher](https://cyclonedx.org/docs/1.6/json/#components_items_publisher)
and [description](https://cyclonedx.org/docs/1.6/json/#components_items_description) of the component
(which also encode the human-readable name)
are presented as details in the SBOM renderer.

### Properties
As described in the [Unit Properties](#unit-properties) section,
most unit properties are mapped to various aspects of the SBOM.
Some properties may be mapped to component [properties](https://cyclonedx.org/docs/1.6/json/#components_items_properties)
if they represent information not otherwise mapped and not recognized to be of direct interest.

The CBI p2 SBOM generator also captures some additional information as component properties.

#### Clearly Defined 

The generator will attempt to query the following URI:

`https://api.clearlydefined.io/definitions/maven/mavencentral/<groupId>/<artifactId>/<version>`

If that returns license details, 
the generator will record the license expression as `clearly-defined`.
This is the behavior for the current prototype and will be integrated with the [license](#licenses) in the longer term.

#### Touchpoints

The generator will record a unit's touchpoints, if present, as a `touchpoint` property.
Note that any unit may specify touchpoints, not only metadata units, and not all metadata units specify touchpoints.

### External References

[External references](https://cyclonedx.org/docs/1.6/json/#components_items_externalReferences) are computed for each mapped component on a best-effort basis.
There are **many** available sources of potential external reference information:
- The p2 `org.eclipse.equinox.p2.doc.url` metadata.
- The OSGi `MANIFEST.MF` `Bundle-DocURL`, `Bundle-SCM`, and `Eclipse-SourceReferences` headers.
- Various elements, e.g., `connection`, in a POM.

### Dependencies

As mentioned previously,
there is a significant impedance mismatch between the concept of OSGi/p2 requirements
versus the concept of SBOM [dependencies](https://cyclonedx.org/docs/1.6/json/#dependencies).
The CBI p2 SBOM generator will generate a [dependency reference](https://cyclonedx.org/docs/1.6/json/#dependencies_items_ref) from each component
to the zero or more components that it [depends on](https://cyclonedx.org/docs/1.6/json/#dependencies_items_dependsOn).
This is accomplished by resolving the requirements of the component's corresponding unit(s)
to the corresponding component(s) of the unit(s) that provide a capability that satisfies that requirement.
As such,
while a unit's requirement may be satisfied by an unbounded number of potential capability providers,
the generator will limit resolution to those available in the SBOM.
To avoid losing potentially-important dependency information about unsatisfied requirements,
any such a requirement is recorded as an `unsatisfied-requirement` [property](#properties) on the corresponding component.

From this perspective, it should be clear that the quality of the generator's dependency information is effectively limited by a closed-universe assumption.
In other words,
it should be noted that the dependency information of an SBOM generated from a p2 repository for which all requirements **do not** transitively resolve is of limited utility.

From the point of view of managing and tracking [Common Vulnerabilities and Exposures](https://www.cve.org/), CVEs,
the actual details of the unit's requirements provide significantly more value than is captured in the SBOM dependencies.
Specifically,
suppose that a new version of some library that addresses some CVE becomes available,
the question of whether that library's version is such that it can be substituted,
i.e., lies within the permissible version range,
becomes highly significant,
and this cannot be answered by the details in the SBOM itself.

Although the SBOM represents dependencies in only one direction, 
the SBOM renderer shows dependencies in both directions,
i.e., both incoming and outgoing dependencies.


## Tycho SBOM

The Tycho 5.x release directly supports
[CycloneDX SBOM generation](https://github.com/eclipse-tycho/tycho/blob/tycho-5.0.x/RELEASE_NOTES.md#support-for-cyclonedx-maven-plugin)
via the 
[tycho-sbom](https://github.com/eclipse-tycho/tycho/tree/main/tycho-sbom)
mojo.
It provides
[an example](https://github.com/eclipse-tycho/tycho/tree/main/tycho-its/projects/sbom)
of how to use it.
Applying this to the Eclipse Installer has provided a useful basis for comparing the SBOMs generated by Tycho with that generated by the CBI p2 SBOM generator.

### Tycho SBOM Comparison

The Tycho SBOMs don't properly use the bom-ref of the component for specifying dependencies but rather use two different styles,
either the `pkg:maven` or `pkg:p2` for a given component.
Also, it has references to components that don't exist in the final distribution, e.g., `*.source` bundles.
In the end, we can't really even hack a workaround because the SBOM does not contain the bundle symbolic name of the component, only the Maven coordinates.
The Tycho SBOMs seem to have odd components that aren't actually in the product repository,
e.g., com.sun.xml.bind,
probably as a result of resolving package requirements to all possible providers in the target platform,
and lots of `*.source` bundles that aren't in the product.
More care must be taken when generating PURLs to ensure that the Maven artifact has the same hash sums as the p2/local artifact,
i.e., is unmodified.
