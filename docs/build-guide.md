# Maven/Jenkins Integration

Because the CBI p2 SBOM Generator can be applied directly to the artifacts already produced by existing continuous integration processes,
it is easy to integrate SBOM generation into a project's build processes.


## Proof of Concept

The following jobs are used to test the generator with various combinations of command-line options
and provide a basis for producing your own jobs:

- https://ci.eclipse.org/cbi/view/p2RepoRelated/job/cbi.p2repo.sbom-generator/
- https://ci.eclipse.org/cbi/view/p2RepoRelated/job/cbi.p2repo.sbom-general-generator/


## Projects Using the CBI p2 SBOM Generator

The SBOM generator is used by the following projects to produce SBOMs for publication to [https://sbom.eclipse.org](https://sbom.eclipse.org),
providing samples that serve as a basis for other projects to generate SBOMs and to publish them to Dependency-Track.

### Orbit

Orbit uses a self-contained [Jenkins pipeline](https://github.com/eclipse-orbit/orbit-simrel/blob/main/orbit-aggregation/OrbitAggregationSBOM.jenkinsfile)
to generate SBOMs published to [sbom.eclipse.org](https://sbom.eclipse.org/projects/a598db3e-3857-4ef2-a8ad-c75db18cdd35/collectionprojects).

- [orbit-sbom](https://ci.eclipse.org/orbit/job/orbit-sbom/)


### SimRel

SimRel uses a self-contained [Jenkins pipeline](https://github.com/eclipse-simrel/simrel.build/blob/main/Jenkinsfile-sbom/)
to generate SBOMs published to [sbom.eclipse.org](https://sbom.eclipse.org/projects/e1ac111b-8567-403c-8df7-950588c102e9/collectionprojects).

- [simrel.sbom](https://ci.eclipse.org/simrel/job/simrel.sbom/)

The job provides more details and relevant links in its description.
