package org.eclipse.cbi.p2repo.sbom;

import static org.eclipse.cbi.p2repo.sbom.ArgumentUtil.getArgument;
import static org.eclipse.cbi.p2repo.sbom.ArgumentUtil.getArguments;
import static org.eclipse.cbi.p2repo.sbom.BOMUtil.addExternalReference;
import static org.eclipse.cbi.p2repo.sbom.BOMUtil.addHashes;
import static org.eclipse.cbi.p2repo.sbom.BOMUtil.createBomXMLGenerator;
import static org.eclipse.cbi.p2repo.sbom.BOMUtil.createProperty;
import static org.eclipse.cbi.p2repo.sbom.BOMUtil.urlEncodeQueryParameter;
import static org.eclipse.cbi.p2repo.sbom.IOUtil.extractInstallation;
import static org.eclipse.cbi.p2repo.sbom.IOUtil.getZipContents;
import static org.eclipse.cbi.p2repo.sbom.URIUtil.parseRedirections;
import static org.eclipse.cbi.p2repo.sbom.URIUtil.toURI;
import static org.eclipse.cbi.p2repo.sbom.XMLUtil.evaluate;
import static org.eclipse.cbi.p2repo.sbom.XMLUtil.getText;
import static org.eclipse.cbi.p2repo.sbom.XMLUtil.newDocumentBuilder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.jar.JarInputStream;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.parsers.ParserConfigurationException;

import org.cyclonedx.Version;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.model.Ancestors;
import org.cyclonedx.model.AttachmentText;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Component.Scope;
import org.cyclonedx.model.Component.Type;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.License;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.Pedigree;
import org.cyclonedx.model.component.data.ComponentData;
import org.cyclonedx.model.component.data.ComponentData.ComponentDataType;
import org.cyclonedx.model.component.data.Content;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.MultiStatus;
import org.eclipse.core.runtime.NullProgressMonitor;
import org.eclipse.core.runtime.OperationCanceledException;
import org.eclipse.core.runtime.Status;
import org.eclipse.core.runtime.SubMonitor;
import org.eclipse.equinox.internal.p2.artifact.repository.simple.SimpleArtifactRepository;
import org.eclipse.equinox.internal.p2.core.DefaultAgentProvider;
import org.eclipse.equinox.internal.p2.director.PermissiveSlicer;
import org.eclipse.equinox.internal.p2.director.QueryableArray;
import org.eclipse.equinox.internal.p2.metadata.IRequiredCapability;
import org.eclipse.equinox.internal.p2.metadata.InstallableUnit;
import org.eclipse.equinox.internal.p2.metadata.repository.io.MetadataWriter;
import org.eclipse.equinox.p2.core.IAgentLocation;
import org.eclipse.equinox.p2.core.IProvisioningAgent;
import org.eclipse.equinox.p2.core.ProvisionException;
import org.eclipse.equinox.p2.engine.IProfile;
import org.eclipse.equinox.p2.internal.repository.tools.AbstractApplication;
import org.eclipse.equinox.p2.internal.repository.tools.RepositoryDescriptor;
import org.eclipse.equinox.p2.metadata.IArtifactKey;
import org.eclipse.equinox.p2.metadata.IInstallableUnit;
import org.eclipse.equinox.p2.metadata.IRequirement;
import org.eclipse.equinox.p2.metadata.ITouchpointData;
import org.eclipse.equinox.p2.metadata.ITouchpointInstruction;
import org.eclipse.equinox.p2.metadata.ITouchpointType;
import org.eclipse.equinox.p2.metadata.MetadataFactory;
import org.eclipse.equinox.p2.metadata.MetadataFactory.InstallableUnitDescription;
import org.eclipse.equinox.p2.publisher.actions.JREAction;
import org.eclipse.equinox.p2.query.IQuery;
import org.eclipse.equinox.p2.query.IQueryResult;
import org.eclipse.equinox.p2.query.QueryUtil;
import org.eclipse.equinox.p2.repository.ICompositeRepository;
import org.eclipse.equinox.p2.repository.IRepository;
import org.eclipse.equinox.p2.repository.IRepositoryManager;
import org.eclipse.equinox.p2.repository.artifact.IArtifactDescriptor;
import org.eclipse.equinox.p2.repository.artifact.IArtifactRepository;
import org.eclipse.equinox.p2.repository.artifact.IArtifactRepositoryManager;
import org.eclipse.equinox.p2.repository.artifact.spi.ArtifactDescriptor;
import org.eclipse.equinox.p2.repository.metadata.IMetadataRepository;
import org.eclipse.equinox.p2.repository.metadata.IMetadataRepositoryManager;
import org.eclipse.equinox.spi.p2.publisher.PublisherHelper;
import org.eclipse.osgi.util.ManifestElement;
import org.json.JSONObject;
import org.osgi.framework.Constants;
import org.osgi.framework.FrameworkUtil;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class SBOMGenerator extends AbstractApplication {

	private static final Comparator<IArtifactKey> ARTIFACT_COMPARATOR = (o1, o2) -> {
		var result = o1.getClassifier().compareTo(o2.getClassifier());
		if (result == 0) {
			result = o1.getId().compareTo(o2.getId());
			if (result == 0) {
				result = o1.getVersion().compareTo(o2.getVersion());
			}
		}
		return result;
	};

	private static final char ZERO_WIDTH_SPACE = '\u200B';

	private static final String A_JRE_JAVASE_ID = "a.jre.javase";

	private static final Pattern ACCEPTED_LICENSE_URL_PATTERN = Pattern.compile(
			".*(documents/e[dp]l-v10|epl-v20|epl-2.0|legal|licen[cs]e|/MPL|CDDLv1.0)(.*[^/])?",
			Pattern.CASE_INSENSITIVE);

	private static final Pattern IGNORED_LICENSE_URL_PATTERN = Pattern.compile(String.join("|", List.of(//
			"https://code.visualstudio.com/api/language-extensions/language-configuration-guide", //
			"https://commons.apache.org/collections", //
			"https://commons.apache.org/proper/commons-codec", //
			"https://developers.google.com/closure/compiler", //
			"https://eclipse-ee4j.github.io/jaxb-ri/jaxb-bundles/jaxb-impl", //
			"https://eclipse.org/equinox/p2/repository_packaging.html", //
			"https://en.wikipedia.org/wiki/TextMate#Language_Grammars", //
			"https://fortawesome.github.io/Font-Awesome", //
			"https://github.com/eclipse-ee4j/jaf/jakarta.activation", //
			"https://groups.google.com/forum/.*", //
			"https://jakarta.apache.org/commons/logging", //
			"https://java.sun.com/products/javamail/javamail-1_4.html", //
			"https://jcp.org/aboutJava/communityprocess/.*", //
			"https://jcp.org/.*/jsr/.*", //
			"https://lasr.cs.ucla.edu/geoff/ispell.html", //
			"https://live.gnome.org/LibSoup", //
			"https://projects.eclipse.org/projects/ee4j.*", //
			"https://scripts.sil.org/OFL", //
			"https://sourceforge.net/projects/(lpg|wsdl4j)", //
			"https://svn.apache.org/repos/asf/tomcat/trunk/java/javax/servlet", //
			"https://wiki.eclipse.org/.*", //
			"https://ws.apache.org/axis", //
			"https://ws.apache.org/xmlrpc/.*", //
			"https://www.antlr.org/download/index.html", //
			"https://www.eclipse.org/(collections|eclipselink).*", //
			"https://www.nayuki.io/page/deflate-library-java", //
			"https://www.nuget.org/packages/Microsoft.Web.WebView2/1.0.721-prerelease", //
			"https://www.openmobilealliance.org/tech/affiliates/wap/wapindex.html", //
			"https://xerces.apache.org/xerces-j", //
			"https://xml.apache.org/xalan-j", //
			"https://[^/]+", //
			"https://github.com/[^/]+/[^/]+(/(commit/.*|issues|tree/.*))?", //
			".*\\.(xsd|dtd|java|xml)", //
			"https://github.com/microsoft/vscode/tree/.*", //
			"https://mail-archives.apache.org/.*", //
			"https://schemas.xmlsoap.org/.*", //
			"https://www.w3.org/TR/.*", //
			"https://dev.eclipse.org/mhonarc/.*", //
			"https://www.sun.com/.*", //
			"https://www.omg.org/(docs|spec|technology)/.*", //
			"https://issues.apache.org/.*"//
	)));

	private static final Pattern POTENTIAL_LICENSE_REFERENCE_PATTERN = Pattern
			.compile("href=['\"]https?://(.*?)[/\r\n ]*['\"]");

	private static final Pattern EPL_10_NAME_PATTERN = Pattern.compile("epl-?(1.0|v10).*\\.html?");

	private static final Pattern EPL_20_NAME_PATTERN = Pattern.compile("epl-?(2.0|v20).*\\.html?");

	private static final Pattern EDL_10_NAME_PATTERN = Pattern.compile("edl-?(1.0|v10).*\\.(html?|php)");

	private static final Pattern APACHE_PUBLIC_LICENSE_20_PATTERN = Pattern
			.compile("Apache License\\s+\\*?\\s*Version 2.0, January 2004\\s+\\*?\\s*http://www.apache.org/licenses/");

	private static final Pattern GPL_21_PATTERN = Pattern
			.compile("\\s*GNU LESSER GENERAL PUBLIC LICENSE\\s+Version 2\\.1, February 1999");

	private static final Pattern SPDX_ID_PATTERN = Pattern
			.compile("SPDX-License-Identifier:\\s((with\r?\n|[^\r\n\"\\\\|#])+)");

	private static final Pattern FEATURE_JAR_PATTERN = Pattern.compile("(.*\\.feature)\\.jar");

	private static final Pattern SOURCE_IU_PATTERN = Pattern.compile("(.*)\\.source(\\.feature\\.group|)");

	private static final Pattern GITHUB_SCM_PATTERN = Pattern
			.compile("(scm:)?(git:)?https?://github\\.com/(?<repo>[^/]+/[^/]+?)(\\.git)?");

	private static final Pattern TOUCHPOINT_FORMATTTING_PATTERN = Pattern.compile("\n( *)");

	private static final String METADATA_ARTIFACT = "metadata";

	/**
	 * https://google.github.io/osv.dev/post-v1-query/
	 * https://ossf.github.io/osv-schema/
	 */
	private static final URI OSV_URI = URI.create("https://api.osv.dev/v1/query");

	private static final Pattern MAVEN_POM_PATTERN = Pattern.compile("META-INF/maven/[^/]+/[^/]+/pom.xml");

	private static final Pattern META_INF_FILE_PATTERN = Pattern.compile("META-INF/[^/]+");

	private static final Pattern LICENSE_FILE_PATTERN = Pattern.compile("(.*/)?LICENSE[^/]*(\\.txt)?$");

	private static final Pattern BUNDLE_PROPERTIES_PATTERN = Pattern.compile("(.*/)?(bundle|plugin).properties$");

	private static List<Map.Entry<Pattern, String>> URL_LICENSE_MAPPINGS = List.of( //
			Map.entry(Pattern.compile(String.join("|", List.of( //
					"https://opensource.org/licenses?/EPL-2.0", //
					"https://eclipse.org/legal/epl/notice.php", //
					"https://projects.eclipse.org/license/epl-2.0", //
					"https://www.eclipse.org/(org/documents|legal)/epl-(2.0(/?|/EPL-2.0.txt)|v20.html)"))), //
					"EPL-2.0"),
			Map.entry(Pattern.compile(String.join("|", List.of( //
					"https://(www[.])?apache.org/licenses(/LICENSE-2.0([.].*)?)?", //
					"https://repository.jboss.org/licenses/apache-2.0.txt", //
					"https://opensource.org/licenses?/apache2.0.php", //
					"https://opensource.org/licenses?/Apache-?2.0", //
					"https://maven.apache.org/license.html", //
					"https://jakarta.apache.org/commons/license.html", //
					"https://ant.apache.org/license.html", //
					"https://jakarta.apache.org/ant/manual/LICENSE"))), //
					"Apache-2.0"), //
			Map.entry(Pattern.compile(String.join("|", List.of( //
					"https://opensource.org/licenses?/BSD-3-Clause", //
					"https://asm.ow2.io/LICENSE.txt", //
					"https://www.eclipse.org/(org/documents|licenses)/edl-v10[.](html|php)",
					"https://www.antlr.org/license.html", //
					"https://www.jcraft.com/(jsch|jzlib)/LICENSE.txt", //
					"https://raw.githubusercontent.com/dnsjava/dnsjava/master/LICENSE",
					"https://github.com/dom4j/dom4j/blob/(main|master)/LICENSE", //
					"https://raw.githubusercontent.com/jaxen-xpath/jaxen/master/LICENSE.txt", //
					"https://raw.githubusercontent.com/hamcrest/JavaHamcrest/master/LICENSE", //
					"https://raw.github.com/hunterhacker/jdom/master/LICENSE.txt", //
					"https://asm.ow2.io/license.html"))), //
					"BSD-3-Clause"),
			Map.entry(Pattern.compile(String.join("|", List.of( //
					"https://(www[.])?opensource.org/licenses?/(mit/?|mit-license.php|MIT)", //
					"https://jsoup.org/license", //
					"https://jquery.org/license", //
					"https://github.com/burningwave/jvm-driver/blob/(main|master)/LICENSE", //
					"https://www.chiark.greenend.org.uk/~sgtatham/putty/licence.html", //
					"https://www.bouncycastle.org/licence.html",
					"https://github.com/(burningwave/core|weisj/jsvg|toolfactory/(jvm-driver|narcissus))/blob/(main|master)/LICENSE"))), //
					"MIT"),
			Map.entry(Pattern.compile(String.join("|", List.of( //
					"https://opensource.org/licenses/eclipse-1.0.php", //
					"https://www.eclipse.org/(org/documents|legal)/epl-v10[.](html|php)"))), //
					"EPL-1.0"),
			Map.entry(Pattern.compile(String.join("|", List.of( //
					"https://xml.apache.org/dist/LICENSE.txt", //
					"https://www.apache.org/licenses/LICENSE"))), //
					"Apache-1.1"),
			Map.entry(Pattern.compile(String.join("|", List.of( //
					"https://(www[.])?opensource.org/licenses?/(bsd-license.(html|php)|BSD-2-Clause)", //
					"https://www.debian.org/misc/bsd.license"))), //
					"BSD-2-Clause"),
			Map.entry(Pattern.compile(String.join("|", List.of( //
					"https://webkit.org/coding/bsd-license.html", //
					"https://www.gnu.org/licenses/(old-licenses/)?lgpl-2.1([.]html)?"))), //
					"LGPL-2.1-only"),
			Map.entry(Pattern.compile(String.join("|", List.of( //
					"https://www.gnu.org/copyleft/gpl.html", //
					"https://www.gnu.org/copyleft/lesser.html", //
					"https://www.gnu.org/licenses/lgpl.html", //
					"https://www.gnu.org/licenses/lgpl-3.0.txt"))), //
					"LGPL-3.0-or-later"),
			Map.entry(Pattern.compile(String.join("|", List.of( //
					"https://projects.eclipse.org/license/secondary-gpl-2.0-cp", //
					"https://www.gnu.org/software/classpath/license.html"))), //
					"Classpath-exception-2.0"),
			Map.entry(Pattern.compile(String.join("|", List.of( //
					"https://glassfish.dev.java.net/nonav/public/CDDL[+]GPL.html", //
					"https://oss.oracle.com/licenses/CDDL[+]GPL-1.1", //
					"https://glassfish.*/CDDLv1.0.*"))), //
					"CDDL-1.1"),
			Map.entry(Pattern.compile("https://www.mozilla.org/([^/]+/)?MPL/(MPL-)?1.1([.]html|/)?"), //
					"MPL-1.1"),
			Map.entry(Pattern.compile(String.join("|", List.of( //
					"https://h2database.com/html/license.html", //
					"https://www.mozilla.org/([^/]+/)?MPL/(MPL-)?2.0([.]html|/|/index.txt)?"))), //
					"MPL-2.0"),
			Map.entry(Pattern.compile("https://www.w3.org/Consortium/Legal/2002/copyright-software-20021231"), //
					"W3C"),
			Map.entry(
					Pattern.compile(
							"https://www.w3.org/Consortium/Legal/copyright-(software-19980720|documents-19990405)"), //
					"W3C-19980720"),
			Map.entry(Pattern.compile("https://raw.githubusercontent.com/jtidy/jtidy/(main|master)/LICENSE.txt"), //
					"HTMLTIDY"),
			Map.entry(Pattern.compile("https://raw.githubusercontent.com/unicode-org/icu/maint/maint-[^/]+/LICENSE"),
					"Unicode-3.0"),
			Map.entry(Pattern.compile(String.join("|", List.of( //
					"https://www.eclipse.org/legal/cpl-v10.html", //
					"https://(www[.])?opensource.org/licenses?/cpl1.0.(html|txt|php)"))), //
					"CPL-1.0"),
			Map.entry(Pattern.compile("https://oss.software.ibm.com/developerworks/opensource/license10.html"), //
					"IPL-1.0"),
			Map.entry(Pattern.compile("https://jsonp.java.net/license.html"), //
					"CDDL-1.1"),
			Map.entry(Pattern.compile("https://creativecommons.org/publicdomain/zero/1.0/?"), //
					"CC0-1.0"),
			Map.entry(Pattern.compile(String.join("|", List.of( //
					"https://www.w3.org/Consortium/Legal/IPR-FAQ.*", //
					"https://www.opengroup.org/openmotif/supporters/metrolink/license.html"))), //
					""),
			Map.entry(Pattern.compile("https://github.com/stleary/JSON-java/blob/(main|master)/LICENSE"), //
					"Unlicense"));

	private static List<Map.Entry<Pattern, String>> COMPONENT_LICENSE_MAPPINGS = List.of( //
			Map.entry(Pattern.compile(String.join("|", List.of( //
					"plugins/org.eclipse.orbit.sun.security.*", //
					"features/org.eclipse.terminal.feature.*", //
					"binary/epp\\.package\\..*\\.executable.*", //
					"binary/org.eclipse\\.(platform|sdk)\\.(rcp|ide)\\.executable.*", //
					"binary/org\\.eclipse\\.(sdk\\.ide)\\.executable.*", //
					"binary/org\\.eclipse\\.(cdt|platform|rcp|sdk\\.examples)_root_.*"))), //
					"EPL-2.0"),
			Map.entry(Pattern.compile(String.join("|", List.of( //
					"plugins/ch.qos.logback.core.*"))), //
					"EPL-1.0"),
			Map.entry(Pattern.compile(String.join("|", List.of( //
					"plugins/org.antlr.runtime.*"))), //
					"BSD-3-Clause"),
			Map.entry(Pattern.compile(String.join("|", List.of( //
					"plugins/org.aopalliance.*"))), //
					"Unlicense"),
			Map.entry(Pattern.compile(String.join("|", List.of( //
					"plugins/org\\.apache\\.xml\\.(serializer|resolver).*", //
					"plugins/org\\.apache\\.xalan.*"))), //
					"Apache-2.0"),
			Map.entry(Pattern.compile(String.join("|", List.of( //
					"plugins/slf4j.*_1\\..*", //
					"plugins/com.konghq.unirest-java.*"))), //
					"MIT"));

	private static boolean isMetadata(IArtifactDescriptor artifactDescriptor) {
		return METADATA_ARTIFACT.equals(artifactDescriptor.getArtifactKey().getClassifier());
	}

	private final Set<String> allLicenses = ConcurrentHashMap.newKeySet();

	private final Set<String> ignoredLicense = ConcurrentHashMap.newKeySet();

	private final Set<String> rejectedLicense = ConcurrentHashMap.newKeySet();

	private final Set<IMetadataRepository> metadataRepositories = new LinkedHashSet<>();

	private final Map<IArtifactKey, IInstallableUnit> artifactIUs = new TreeMap<>(ARTIFACT_COMPARATOR);

	private final Map<IArtifactKey, IInstallableUnit> includedArtifactIUs = new TreeMap<>(ARTIFACT_COMPARATOR);

	private final Map<IArtifactKey, IArtifactDescriptor> artifactDescriptors = new HashMap<>();

	private final Map<IInstallableUnit, IInstallableUnit> featureJarsToFeatures = new HashMap<>();

	private final Map<IInstallableUnit, IInstallableUnit> featuresToFeatureJars = new HashMap<>();

	private final Map<IInstallableUnit, Component> iuComponents = new LinkedHashMap<>();

	private final Set<String> excludedComponents = new LinkedHashSet<>();

	private final List<URI> combinedRepositoryURIs = new ArrayList<>();

	private final List<URI> metadataRepositoryURIs = new ArrayList<>();

	private final List<URI> artifactRepositoryURIs = new ArrayList<>();

	private final List<URI> combinedDependencyRepositoryURIs = new ArrayList<>();

	private final List<URI> metadataDependencyRepositoryURIs = new ArrayList<>();

	private final List<URI> artifactDependencyRepositoryURIs = new ArrayList<>();

	private final Set<IInstallableUnit> dependencyIUs = new TreeSet<>();

	private final Set<IInstallableUnit> usedDependencyIUs = ConcurrentHashMap.newKeySet();

	private final List<URI> p2ArtifactSourceRepositoryURIs = new ArrayList<>();

	private final List<ArtifactSourceRepository> artifactSourceRepositories = new ArrayList<>();

	private final boolean strictSourceRepositories;

	private final List<IInstallableUnit> inclusiveContextIUs = new ArrayList<>();

	private final List<IInstallableUnit> exclusiveContextIUs = new ArrayList<>();

	private final List<Pattern> expectedMissingArtifactIUPatterns = new ArrayList<>();

	private final List<Path> outputs = new ArrayList<>();

	private final List<String> arguments = new ArrayList<>();

	private final LinkedHashSet<IMetadataRepository> sourceMetataRepositories = new LinkedHashSet<>();

	private final URIUtil.URIMap uriRedirections;

	private final ContentHandler contentHandler;

	private final SPDXIndex spdxIndex;

	private final boolean verbose;

	private final boolean queryCentral;

	private final boolean gitIssues;

	private final boolean minimizeRootDependencies;

	private final boolean useRepositoryReferencesAsDependencies;

	private final boolean xml;

	private final String xmlOutput;

	private final boolean json;

	private final String jsonOutput;

	private final URI installationLocation;

	private final boolean processBundleClassPath;

	private final boolean fetchAdvisory;

	private final boolean fetchClearlyDefined;

	private final boolean dependencyTrack;

	private final Pattern rootIUInclusions;

	private final Pattern classifierExclusions;

	private final Pattern componentExclusions;

	private final Bom bom;

	private IMetadataRepositoryManager metadataRepositoryManager;

	private IArtifactRepositoryManager artifactRepositoryManager;

	public SBOMGenerator(List<String> arguments) throws Exception {
		super(createAgent());

		this.arguments.addAll(arguments);

		var args = new ArrayList<>(arguments);

		verbose = getArgument("-verbose", args);

		contentHandler = new ContentHandler(getArgument("-cache", args, null),
				parseRedirections(getArguments("-content-redirections", args, List.of())),
				getArgument("-retry", args, Integer.getInteger("org.eclipse.cbi.p2repo.sbom.retry", 5)),
				getArgument("-retry-delay", args, Integer.getInteger("org.eclipse.cbi.p2repo.sbom.retry.delay", 30)),
				getArgument("-timeout", args, Integer.getInteger("org.eclipse.cbi.p2repo.sbom.timeout", 30)));
		processBundleClassPath = getArgument("-process-bundle-classpath", args);
		spdxIndex = new SPDXIndex(contentHandler);

		queryCentral = getArgument("-central-search", args);

		gitIssues = getArgument("-git-issues", args);

		minimizeRootDependencies = getArgument("-minimize-root-dependencies", args);

		fetchAdvisory = getArgument("-advisory", args);

		fetchClearlyDefined = getArgument("-clearly-defined", args);

		dependencyTrack = getArgument("-dependency-track", args);

		uriRedirections = parseRedirections(getArguments("-redirections", args, List.of()));

		var installation = getArgument("-installation", args, null);
		if (installation != null) {
			installationLocation = handleInstallation(installation);
		} else {
			installationLocation = null;
		}

		rootIUInclusions = Pattern.compile(String.join("|", getArguments("-root-iu-inclusions", args, List.of())));

		classifierExclusions = Pattern
				.compile(getArguments("-classifier-exclusions", args, List.of()).stream().map(it -> switch (it) {
				case "feature" -> "org.eclipse.update.feature";
				case "bundle" -> "osgi.bundle";
				default -> it;
				}).collect(Collectors.joining("|")));
		componentExclusions = Pattern.compile(String.join("|", getArguments("-component-exclusions", args, List.of())));

		for (var requirementInclusions : getArguments("-requirement-inclusions", args, List.of())) {
			inclusiveContextIUs.add(createContextIU(requirementInclusions));
		}

		for (var requirementExclusions : getArguments("-requirement-exclusions", args, List.of())) {
			exclusiveContextIUs.add(createContextIU(requirementExclusions));
		}

		for (var expectedMissingArtifactIUPattern : getArguments("-expected-missing-artifact-iu-patterns", args,
				List.of())) {
			expectedMissingArtifactIUPatterns.add(Pattern.compile(expectedMissingArtifactIUPattern));
		}

		combinedRepositoryURIs.addAll(getArguments("-input", args, List.of()).stream().map(URI::create).toList());
		metadataRepositoryURIs.addAll(getArguments("-metadata", args, List.of()).stream().map(URI::create).toList());
		artifactRepositoryURIs.addAll(getArguments("-artifact", args, List.of()).stream().map(URI::create).toList());

		useRepositoryReferencesAsDependencies = getArgument("-use-repository-references-as-dependencies", arguments);

		combinedDependencyRepositoryURIs
				.addAll(getArguments("-dependency-input", args, List.of()).stream().map(URI::create).toList());
		metadataDependencyRepositoryURIs
				.addAll(getArguments("-dependency-metadata", args, List.of()).stream().map(URI::create).toList());
		artifactDependencyRepositoryURIs
				.addAll(getArguments("-dependency-artifact", args, List.of()).stream().map(URI::create).toList());

		p2ArtifactSourceRepositoryURIs
				.addAll(getArguments("-p2sources", args, getArguments("-p2-sources", args, List.of())).stream()
						.map(URI::create).toList());
		strictSourceRepositories = getArgument("-strict-p2-source-repositories", args);

		xmlOutput = getArgument("-xml-output", args, null);
		jsonOutput = getArgument("-json-output", args, null);
		json = getArgument("-json", args);
		xml = getArgument("-xml", args) || !json && xmlOutput == null && jsonOutput == null;

		bom = createBOM();
	}

	private Bom createBOM() {
		var bom = new Bom();
		var randomUUID = UUID.randomUUID();
		bom.setSerialNumber("urn:uuid:" + randomUUID);
		var metadata = new Metadata();
		bom.setMetadata(metadata);
		metadata.setTimestamp(new Date());

		var component = new Component();
		metadata.setComponent(component);
		var bundle = FrameworkUtil.getBundle(getClass());
		component.setGroup("org.eclipse");
		component.setName(bundle.getSymbolicName());
		component.setVersion(bundle.getVersion().toString());
		component.setType(Component.Type.APPLICATION);
		component.setBomRef("meta.root.component");

		return bom;
	}

	@Override
	public IStatus run(IProgressMonitor monitor) throws ProvisionException {
		var progress = SubMonitor.convert(monitor, 100);

		if (combinedRepositoryURIs.isEmpty() && metadataRepositoryURIs.isEmpty()) {
			System.err.println("An '-input' or '-metadata' argument is required");
			return Status.CANCEL_STATUS;
		}

		loadRepositories(progress.split(10, SubMonitor.SUPPRESS_NONE));

		processArtifacts(analyzeArtifacts(progress.split(5, SubMonitor.SUPPRESS_NONE)),
				progress.split(80, SubMonitor.SUPPRESS_NONE));

		if (verbose) {
			System.out.println("licenses");
			new TreeSet<>(allLicenses).stream().forEach(System.out::println);

			if (!rejectedLicense.isEmpty()) {
				System.out.println();
				System.out.println("rejected-url");
				new TreeSet<>(rejectedLicense).stream().forEach(System.out::println);
				if (Boolean.FALSE) {
					for (var license : new TreeSet<>(rejectedLicense)) {
						System.out.println('"' + license + '"' + ", //");
					}
				}
			}
		}

		if (dependencyTrack) {
			transformForDependencyTrack();
		}

		computeRootComponents();

		save(progress.split(5, SubMonitor.SUPPRESS_NONE));

		progress.setTaskName("Done");

		return Status.OK_STATUS;
	}

	public Result generate(IProgressMonitor monitor) throws ProvisionException {
		run(monitor);
		return new Result(this);
	}

	private void loadRepositories(IProgressMonitor monitor) throws ProvisionException {
		var progress = SubMonitor.convert(monitor, "Loading Repositories",
				combinedRepositoryURIs.size() * 2 + metadataRepositoryURIs.size() * 2 + artifactRepositoryURIs.size()
						+ combinedDependencyRepositoryURIs.size() * 2 + metadataDependencyRepositoryURIs.size() * 2
						+ artifactDependencyRepositoryURIs.size());

		loadRepositories(combinedRepositoryURIs, metadataRepositoryURIs, artifactRepositoryURIs, progress);

		var artifactRepositoryManager = getArtifactRepositoryManager();
		var rootLocation = agent.getService(IAgentLocation.class).getRootLocation();
		for (var uri : artifactRepositoryManager.getKnownRepositories(IRepositoryManager.REPOSITORIES_ALL)) {
			if (installationLocation == null && rootLocation.relativize(uri) != uri
					|| isExcludedArtifactRepository(uri)) {
				artifactRepositoryManager.removeRepository(uri);
				removeRepository(uri);
			} else {
				var repository = artifactRepositoryManager.loadRepository(uri, null);
				var type = repository.getType();
				if ("org.eclipse.equinox.p2.extensionlocation.artifactRepository".equals(type)
						&& installationLocation != null && installationLocation.relativize(uri) == uri) {
					artifactRepositoryManager.removeRepository(uri);
					removeRepository(uri);
				}
			}
		}

		for (var repository : getSourceMetadataRepositories()) {
			metadataRepositories.addAll(gatherSimpleRepositories(new HashSet<>(), new TreeMap<>(), repository));
		}

		if (useRepositoryReferencesAsDependencies) {
			// Automatically find dependency repository URIs from the repository references
			// in the metadata repositories we've already loaded.
			for (var repository : metadataRepositories) {
				for (var reference : repository.getReferences()) {
					switch (reference.getType()) {
					case IRepository.TYPE_METADATA: {
						metadataDependencyRepositoryURIs.add(reference.getLocation());
						break;
					}
					case IRepository.TYPE_ARTIFACT: {
						artifactDependencyRepositoryURIs.add(reference.getLocation());
						break;
					}
					}
				}
			}
		}

		addJRE(monitor);

		// Compute the current IUs before loading the dependency repositories.
		var actualIUs = query(QueryUtil.ALL_UNITS, null).toSet();

		loadRepositories(combinedDependencyRepositoryURIs, metadataDependencyRepositoryURIs,
				artifactDependencyRepositoryURIs, progress);

		// The dependencies IUs are all the additional IUs that were not already present
		// before the dependency repositories were loaded.
		dependencyIUs.addAll(query(QueryUtil.ALL_UNITS, null).toSet());
		dependencyIUs.removeAll(actualIUs);

		for (var repository : getSourceMetadataRepositories()) {
			metadataRepositories.addAll(gatherSimpleRepositories(new HashSet<>(), new TreeMap<>(), repository));
		}

		loadSourceRepositories();

		progress.done();
	}

	private void loadRepositories(List<URI> combinURIs, List<URI> metadataURIs, List<URI> artifactURIs,
			SubMonitor progress) throws ProvisionException {
		for (var uri : combinURIs) {
			loadRepositories(uri, Set.of(IRepository.TYPE_METADATA, IRepository.TYPE_ARTIFACT),
					progress.split(1, SubMonitor.SUPPRESS_NONE));
		}
		for (var uri : metadataURIs) {
			loadRepositories(uri, Set.of(IRepository.TYPE_METADATA), progress.split(1, SubMonitor.SUPPRESS_NONE));
		}
		for (var uri : artifactURIs) {
			loadRepositories(uri, Set.of(IRepository.TYPE_ARTIFACT), progress.split(1, SubMonitor.SUPPRESS_NONE));
		}
	}

	private void buildArtifactMappings() {
		var artifactRepository = getCompositeArtifactRepository();
		var metadataArtifacts = new HashSet<IInstallableUnit>();
		for (var iu : queryRootIUs().toSet()) {
			if ("true".equals(iu.getProperty(QueryUtil.PROP_TYPE_CATEGORY)) || //
					A_JRE_JAVASE_ID.equals(iu.getId())) {
				continue;
			}

			var artifactKeys = iu.getArtifacts();
			var associated = false;
			for (var artifactKey : artifactKeys) {
				for (var artifactDescriptor : artifactRepository.getArtifactDescriptors(artifactKey)) {
					// Only process the canonical descriptor, i.e., not the pack200.
					var format = artifactDescriptor.getProperty(IArtifactDescriptor.FORMAT);
					if (format == null) {
						associate(iu, artifactDescriptor);
						associated = true;

						// Create the two-way map between feature IU and feature jar IU.
						var id = iu.getId();
						var matcher = FEATURE_JAR_PATTERN.matcher(id);
						if (matcher.matches()) {
							var iuQuery = QueryUtil.createIUQuery(matcher.group(1) + ".group", iu.getVersion());
							var set = query(iuQuery, null).toSet();
							if (set.size() != 1) {
								if (verbose) {
									System.err.println("featureless-jar=" + iu);
								}
							} else {
								var feature = set.iterator().next();
								featureJarsToFeatures.put(iu, feature);
								featuresToFeatureJars.put(feature, iu);
							}
						}

						break;
					}
				}
			}

			if (!associated) {
				metadataArtifacts.add(iu);
			}
		}

		metadataArtifacts.removeAll(featuresToFeatureJars.keySet());
		for (var iu : metadataArtifacts) {
			associate(iu, createMetadataArtifactDecriptor(iu));
		}
	}

	private Map<IInstallableUnit, Dependency> analyzeArtifacts(IProgressMonitor monitor) {
		var progress = SubMonitor.convert(monitor, "Analyzing Artifacts", 2);
		var iusToDependencies = new LinkedHashMap<IInstallableUnit, Dependency>();
		buildArtifactMappings();
		progress.worked(1);

		// Build the basic component information available without I/O.
		for (var entry : artifactIUs.entrySet()) {
			var iu = entry.getValue();
			var component = createComponent(iu);
			iuComponents.put(iu, component);

			var artifactKey = entry.getKey();
			var artifactDescriptor = artifactDescriptors.get(artifactKey);
			var bomRef = setBomRef(component, artifactDescriptor);

			var dependency = new Dependency(bomRef);
			iusToDependencies.put(iu, dependency);

			if (isMetadata(artifactDescriptor)) {
				var artifacts = iu.getArtifacts();
				var id = iu.getId();
				if (id.endsWith(".feature.group")) {
					if (!isExpectedMissingArtifact(iu)) {
						component.addProperty(createProperty("missing-artifact", "org.eclipse.update.feature,"
								+ id.replaceAll("\\.feature\\.group", "") + "," + iu.getVersion()));
					}
				} else if (!artifacts.isEmpty() && !isExpectedMissingArtifact(iu)) {
					component.addProperty(createProperty("missing-artifact",
							String.join(";", artifacts.stream().map(Object::toString).toList())));
				}
			}

			var isExcluded = componentExclusions.matcher(iu.getId()).matches()
					|| classifierExclusions.matcher(artifactKey.getClassifier()).matches();
			if (isExcluded) {
				excludedComponents.add(bomRef);
			} else {
				includedArtifactIUs.put(artifactKey, iu);
				if (!dependencyIUs.contains(iu)) {
					bom.addComponent(component);
					bom.addDependency(dependency);
				}
			}
		}

		progress.done();
		return iusToDependencies;
	}

	private void processArtifacts(Map<IInstallableUnit, Dependency> iusToDependencies, IProgressMonitor monitor)
			throws ProvisionException {
		new ArtifactAnalyzer(iusToDependencies, monitor).analyze();
	}

	private class ArtifactAnalyzer {
		private final AtomicInteger completed = new AtomicInteger();
		private final AtomicInteger inProgress = new AtomicInteger();
		private final AtomicInteger remaining = new AtomicInteger(includedArtifactIUs.size());
		private final SubMonitor progress;
		private final Map<IInstallableUnit, Dependency> iusToDependencies;

		public ArtifactAnalyzer(Map<IInstallableUnit, Dependency> iusToDependencies, IProgressMonitor monitor) {
			this.iusToDependencies = iusToDependencies;
			progress = SubMonitor.convert(monitor, "Processing Artifacts", includedArtifactIUs.size());
		}

		private void update() {
			progress.subTask(" Completed: " + completed.get() + " Processing: " + inProgress.get() + " Remaining: "
					+ remaining.get());
		}

		private Dependency getDependencies(IInstallableUnit iu) {
			var featureJar = featuresToFeatureJars.get(iu);
			return iusToDependencies.get(featureJar == null ? iu : featureJar);
		}

		private void completed() {
			progress.worked(1);
			completed.incrementAndGet();
			inProgress.decrementAndGet();
			remaining.decrementAndGet();
			update();
		}

		public void analyze() throws ProvisionException {
			analyze(false);
			if (!usedDependencyIUs.isEmpty()) {
				analyze(true);
				for (var iu : usedDependencyIUs) {
					var component = getComponent(iu);
					bom.addComponent(component);
					bom.addDependency(getDependencies(iu));
				}
			}

			// Transfer gathered details from binary IU to corresponding source IU.
			var includedIUs = new HashSet<>(includedArtifactIUs.values());
			for (var entry : iuComponents.entrySet()) {
				var iu = entry.getKey();
				if (includedIUs.contains(iu)) {
					var component = entry.getValue();
					transferDetailsFromBinaryToSource(component, iu);
				}
			}

			progress.subTask("");
			progress.done();
		}

		private void analyze(boolean processDependencyIUs) throws ProvisionException {
			// Gather details from the actual artifacts in parallel.
			var executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 4);
			var futures = new LinkedHashSet<Future<?>>();
			for (var entry : includedArtifactIUs.entrySet()) {
				var iu = entry.getValue();
				if (processDependencyIUs) {
					if (!dependencyIUs.contains(iu)) {
						// Already processed and already accounted for in the progress.
						continue;
					}
					if (!usedDependencyIUs.contains(iu)) {
						// Will be ignored again, so counted as completed now.
						inProgress.incrementAndGet();
						completed();
						continue;
					}
				} else if (dependencyIUs.contains(iu)) {
					// Ignore during the first pass to process on the next pass.
					continue;
				}

				var component = getComponent(iu);
				var artifactDescriptor = artifactDescriptors.get(entry.getKey());
				futures.add(executor.submit(() -> {
					if (verbose) {
						System.out.println("Processing " + component.getBomRef());
					}

					inProgress.incrementAndGet();
					update();

					var bytes = getArtifactContent(component, artifactDescriptor);
					setPurl(component, iu, artifactDescriptor, bytes);

					var mavenDescriptor = MavenDescriptor.create(iu, artifactDescriptor, bytes, queryCentral,
							contentHandler);
					gatherLicenses(component, mavenDescriptor, iu, bytes);
					gatherInnerJars(component, bytes, artifactDescriptor);
					gatherAdvisory(component);
					resolveDependencies(getDependencies(iu), iu, processDependencyIUs);

					completed();
				}));
			}

			executor.shutdown();

			try {
				executor.awaitTermination(10, TimeUnit.MINUTES);
				var multiStatus = new MultiStatus(getClass(), 0, "Problems");
				var canceled = false;
				for (var future : futures) {
					try {
						future.get();
					} catch (ExecutionException e) {
						var message = e.getMessage();
						if (e.getCause() instanceof OperationCanceledException) {
							canceled = true;
						} else {
							if (verbose) {
								System.err.println("Execution exception: " + message);
							}
							multiStatus.add(new Status(IStatus.ERROR, getClass(), message, e));
						}
					}
				}

				if (canceled) {
					throw new OperationCanceledException();
				}

				if (!multiStatus.isOK()) {
					throw new ProvisionException(multiStatus);
				}
			} catch (InterruptedException ex) {
				throw new ProvisionException("Analysis took more than 10 minutes to complete", ex);
			}
		}
	}

	private void transformForDependencyTrack() {
		var components = bom.getComponents();
		var dependencies = bom.getDependencies();
		var dependenciesMap = dependencies.stream().collect(Collectors.toMap(Dependency::getRef, Function.identity()));
		var componentHandler = new Object() {
			public void promoteComponent(Component mainComponent, String type, Component subComponent) {
				// Create a dependency from the main component tot he subComponent.
				var dependency = dependenciesMap.get(mainComponent.getBomRef());
				var subComponentBomRef = subComponent.getBomRef();
				dependency.addDependency(new Dependency(subComponentBomRef));

				// Annotate and promote the subComponent and define empty associated
				// dependencies for it.
				subComponent.addProperty(createProperty(type, "true"));
				components.add(subComponent);
				dependencies.add(new Dependency(subComponentBomRef));
			}
		};
		var pedigreeHandler = new Object() {
			public void handlePedigree(Component mainComponent, String type, Component pedigreeCompoonent) {
				var pedigree = pedigreeCompoonent.getPedigree();
				if (pedigree != null) {
					pedigreeCompoonent.setPedigree(null);
					var ancestors = pedigree.getAncestors();
					if (ancestors != null) {
						var ancestorComponents = ancestors.getComponents();
						if (ancestorComponents != null) {
							for (var ancestorComponent : ancestorComponents) {
								var purl = ancestorComponent.getPurl();
								// A pedigree is created only if the Maven PURL is known.
								if (purl != null) {
									componentHandler.promoteComponent(mainComponent, type, ancestorComponent);
								}
							}
						}
					}

				}
			}
		};

		for (var component : components.toArray(Component[]::new)) {
			pedigreeHandler.handlePedigree(component, "ancestor", component);
			var nestedComponents = component.getComponents();
			if (nestedComponents != null) {
				component.setComponents(null);
				for (var nestedComponent : nestedComponents) {
					var purl = nestedComponent.getPurl();
					if (purl != null) {
						// If there is a PURL, the nested jar is one known to come directly from Maven.
						componentHandler.promoteComponent(component, "nested-jar", nestedComponent);
					} else {
						// If there is no pedigree, the nested jar is ignored because we have no useful
						// information about it in terms of dependency-track..
						pedigreeHandler.handlePedigree(component, "nested-jar", nestedComponent);
					}
				}
			}
		}
	}

	private void computeRootComponents() {
		// When minimizing the root components, need to compute roots taking into
		// consideration that there may be circular dependencies.
		var roots = new LinkedHashSet<String>();
		var dependencies = new LinkedHashMap<String, List<String>>();
		for (var dependency : bom.getDependencies()) {
			var ref = dependency.getRef();
			roots.add(ref);
			if (minimizeRootDependencies) {
				var dependsOn = dependency.getDependencies();
				if (dependsOn != null) {
					dependencies.put(ref, dependsOn.stream().map(Dependency::getRef)
							.collect(Collectors.toCollection(ArrayList::new)));
				}
			}
		}

		if (minimizeRootDependencies) {
			for (var entry : dependencies.entrySet()) {
				// If the entry is for a ref that is already removed from the roots, then we
				// don't need to visit it because we already have.
				var ref = entry.getKey();
				if (roots.contains(ref)) {
					var reachable = gatherReachableDependencies(new HashSet<>(), dependencies, entry.getValue());
					// Remove the ref which may be present due to circularity.
					reachable.remove(ref);
					// Everything reachable from this ref is not a root.
					roots.removeAll(reachable);
				}
			}
		}

		// Add the root dependencies for the metadata root component.
		var rootDependency = new Dependency(bom.getMetadata().getComponent().getBomRef());
		bom.getDependencies().add(0, rootDependency);
		rootDependency.setDependencies(roots.stream().map(Dependency::new).toList());
	}

	private Set<String> gatherReachableDependencies(Set<String> visited, Map<String, List<String>> dependencies,
			List<String> dependsOn) {
		if (dependsOn != null && !dependsOn.isEmpty()) {
			var dependsOnCopy = dependsOn.toArray(String[]::new);
			// Don't visit these again.
			dependsOn.clear();
			for (var dependency : dependsOnCopy) {
				if (visited.add(dependency)) {
					gatherReachableDependencies(visited, dependencies, dependencies.get(dependency));
				}
			}
		}
		return visited;
	}

	private void save(IProgressMonitor monitor) {
		var progress = SubMonitor.convert(monitor, "Saving SBOMs", 2);
		generateXML(bom);
		progress.worked(1);
		generateJson(bom);
		progress.worked(1);
	}

	@Override
	protected IMetadataRepositoryManager getMetadataRepositoryManager() {
		if (metadataRepositoryManager == null) {
			initRepositoryManagers();
		}
		return metadataRepositoryManager;
	}

	@Override
	protected IArtifactRepositoryManager getArtifactRepositoryManager() {
		if (artifactRepositoryManager == null) {
			initRepositoryManagers();
		}
		return artifactRepositoryManager;
	}

	public List<String> getCommandLineArguments() {
		return arguments;
	}

	public List<Path> getOutputs() {
		return outputs;
	}

	public List<URI> getInputs() {
		var inputs = new LinkedHashSet<URI>();
		if (installationLocation != null) {
			inputs.add(installationLocation);
		} else {
			inputs.addAll(combinedRepositoryURIs);
			inputs.addAll(metadataRepositoryURIs);
			inputs.addAll(artifactRepositoryURIs);
		}
		return inputs.stream().map(uriRedirections::redirect).toList();
	}

	private URI handleInstallation(String installation) throws IOException {
		var root = getInstallationPath(installation);
		var macConfigIni = root.resolve("Contents/Eclipse/configuration/config.ini");
		var unixWinConfigIni = root.resolve("configuration/config.ini");
		var configIni = Files.isRegularFile(macConfigIni) ? macConfigIni : unixWinConfigIni;
		var properties = new Properties();
		try (var input = Files.newInputStream(configIni)) {
			properties.load(input);
		}
		var profileName = properties.getProperty("eclipse.p2.profile");
		var p2DataArea = properties.getProperty("eclipse.p2.data.area");
		var resolvedDataArea = p2DataArea.startsWith("@config.dir/")
				? Path.of(p2DataArea.replaceAll("^@config.dir", configIni.getParent().toString().replace('\\', '/')))
				: Path.of(URI.create(p2DataArea));
		var profileFolder = resolvedDataArea
				.resolve("org.eclipse.equinox.p2.engine/profileRegistry/" + profileName + ".profile").normalize();
		metadataRepositoryURIs.add(toURI(profileFolder));
		return toURI(root);
	}

	private Path getInstallationPath(String installation) throws IOException {
		if (installation.startsWith("https://")) {
			var installationOriginatingURI = URI.create(installation);
			var extractedInstallation = extractInstallation(contentHandler.getContentCache(installationOriginatingURI));
			var installationParentURI = toURI(extractedInstallation.getParent().resolve("."));
			uriRedirections.put(installationParentURI, URI.create("archive:" + installationOriginatingURI + "!/"));
			return extractedInstallation;
		}
		var installationPath = Path.of(installation).toAbsolutePath();
		if (Files.isRegularFile(installationPath)) {
			var installationOriginatingURI = uriRedirections.redirect(toURI(installationPath));
			var extractedInstallation = extractInstallation(installationPath);
			var installationParentURI = toURI(extractedInstallation.getParent().resolve("."));
			uriRedirections.put(installationParentURI, URI.create("archive:" + installationOriginatingURI + "!/"));
			return extractedInstallation;
		}
		return installationPath;
	}

	// Ensure that nothing leaks from previous calls or from some internal defaults.
	// Loading profile metadata can cause artifact repositories to be loaded.
	private void initRepositoryManagers() {
		metadataRepositoryManager = super.getMetadataRepositoryManager();
		for (var uri : metadataRepositoryManager.getKnownRepositories(IRepositoryManager.REPOSITORIES_ALL)) {
			metadataRepositoryManager.removeRepository(uri);
		}
		artifactRepositoryManager = super.getArtifactRepositoryManager();
		for (var uri : artifactRepositoryManager.getKnownRepositories(IRepositoryManager.REPOSITORIES_ALL)) {
			artifactRepositoryManager.removeRepository(uri);
		}
	}

	private void removeRepository(URI uri) {
		sourceRepositories.removeIf(it -> uri.equals(it.getRepoLocation()));
	}

	private void gatherAdvisory(Component component) {
		if (!fetchAdvisory) {
			return;
		}
		try {
			queryOSV(component, contentHandler);
		} catch (IOException | InterruptedException e) {
			System.err.println("Query OSV failed: " + e);
		}
	}

	private void gatherInnerJars(Component component, byte[] bytes, IArtifactDescriptor artifactDescriptor) {
		if (!processBundleClassPath || isMetadata(artifactDescriptor) || !PublisherHelper.OSGI_BUNDLE_CLASSIFIER
				.equals(artifactDescriptor.getArtifactKey().getClassifier())) {
			return;
		}

		var innerComponents = new HashMap<String, byte[]>();
		var innerPOMs = new HashMap<String, byte[]>();
		try (var stream = new JarInputStream(new ByteArrayInputStream(bytes))) {
			var manifest = stream.getManifest();
			if (manifest == null) {
				return;
			}
			var value = manifest.getMainAttributes().getValue(Constants.BUNDLE_CLASSPATH);
			if (value == null) {
				return;
			}
			var jars = Arrays.stream(value.split(",")).map(String::trim).filter(s -> s.endsWith(".jar"))
					.collect(Collectors.toSet());
			if (!jars.isEmpty()) {
				ZipEntry entry;
				while ((entry = stream.getNextEntry()) != null) {
					var name = entry.getName();
					if (!entry.isDirectory()) {
						if (jars.contains(name)) {
							innerComponents.put(name, stream.readAllBytes());
						} else if (name.endsWith(".pom")) {
							innerPOMs.put(name, stream.readAllBytes());
						}
					}
				}
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		if (!innerComponents.isEmpty()) {
			for (var entry : innerComponents.entrySet()) {
				var jar = entry.getKey();
				var nestedJarBytes = entry.getValue();
				var mavenDescriptor = MavenDescriptor.createFromJarName(jar, queryCentral, contentHandler);
				if (mavenDescriptor == null) {
					var pom = innerPOMs.get(jar.replaceAll(".jar$", ".pom"));
					if (pom != null) {
						mavenDescriptor = MavenDescriptor.createFromPOM(pom);
					}

					if (mavenDescriptor == null) {
						mavenDescriptor = MavenDescriptor.createFromBytes(nestedJarBytes, queryCentral, contentHandler);
					}
				}

				var subComponent = mavenDescriptor != null
						? createMavenJarComponent(component, jar, mavenDescriptor, nestedJarBytes)
						: createJarComponent(component, jar);
				gatherLicenses(subComponent, mavenDescriptor, null, nestedJarBytes);
				addHashes(subComponent, nestedJarBytes);
				component.addComponent(subComponent);
			}
		}
	}

	private void loadArtifactSource(URI location, URI referenced, Set<URI> loaded) {
		if (loaded.add(location)) {
			try {
				var artifactManager = getArtifactRepositoryManager();
				var repository = artifactManager.loadRepository(location, new NullProgressMonitor());
				artifactSourceRepositories
						.add(new ArtifactSourceRepository(referenced == null ? location : referenced, repository));
				var metadataManager = getMetadataRepositoryManager();
				var references = metadataManager.loadRepository(location, new NullProgressMonitor()).getReferences();
				for (var reference : references) {
					if (reference.isEnabled()) {
						loadArtifactSource(reference.getLocation(), location, loaded);
					}
				}
			} catch (Exception e) {
				if (referenced == null) {
					System.err.println("Can't load p2 source repository: " + location + " it will be ignored: " + e);
				}
			}
		}
	}

	private Set<IMetadataRepository> getSourceMetadataRepositories() {
		if (sourceMetataRepositories.isEmpty()) {
			var manager = getMetadataRepositoryManager();
			for (var repositoryDescriptor : sourceRepositories) {
				if (repositoryDescriptor.isMetadata()) {
					try {
						sourceMetataRepositories
								.add(manager.loadRepository(repositoryDescriptor.getRepoLocation(), null));
					} catch (ProvisionException e) {
						throw new RuntimeException(e);
					}
				}
			}
		}
		return sourceMetataRepositories;
	}

	private IQueryResult<IInstallableUnit> query(IQuery<IInstallableUnit> query, IProgressMonitor monitor) {
		return QueryUtil.compoundQueryable(getSourceMetadataRepositories()).query(query, monitor);
	}

	private IQueryResult<IInstallableUnit> queryRootIUs() {
		var allIUs = query(QueryUtil.ALL_UNITS, null);
		if (rootIUInclusions.pattern().isEmpty()) {
			return allIUs;
		}

		var rootIUs = allIUs.stream().filter(iu -> {
			var id = iu.getId();
			return rootIUInclusions.matcher(id).matches()
					|| rootIUInclusions.matcher(id + ":" + iu.getVersion()).matches();
		}).collect(Collectors.toSet());

		var slice = new PermissiveSlicer(new QueryableArray(allIUs.query(QueryUtil.ALL_UNITS, null).toSet()), Map.of(),
				true, true, true, false, false) {
			@Override
			protected boolean isApplicable(IRequirement requirement) {
				return !isExcluded(requirement);
			}
		}.slice(rootIUs, null);
		return slice.query(QueryUtil.ALL_UNITS, null);
	}

	private void loadRepositories(URI uri, Set<Integer> types, IProgressMonitor monitor) throws ProvisionException {
		var repositoryDescriptor = new RepositoryDescriptor();
		if (types.size() == 1) {
			if (types.contains(IRepository.TYPE_METADATA)) {
				repositoryDescriptor.setKind(RepositoryDescriptor.KIND_METADATA);
			} else if (types.contains(IRepository.TYPE_ARTIFACT)) {
				repositoryDescriptor.setKind(RepositoryDescriptor.KIND_ARTIFACT);
			}
		}

		repositoryDescriptor.setLocation(uri);
		addSource(repositoryDescriptor);

		var progress = SubMonitor.convert(monitor, "Loading " + uri, types.size());
		if (types.contains(IRepository.TYPE_METADATA)) {
			var metadataRepositoryManager = getMetadataRepositoryManager();
			var repository = metadataRepositoryManager.loadRepository(uri, progress.split(1));
			var properties = repository.getProperties();
			var environments = properties.get(IProfile.PROP_ENVIRONMENTS);
			if (environments != null) {
				inclusiveContextIUs.add(createContextIU(environments));
				var references = repository.getReferences();
				for (var reference : references) {
					if (reference.getType() == IRepository.TYPE_ARTIFACT) {
						var locationURI = toURI(reference.getLocation());
						var cache = properties.get(IProfile.PROP_CACHE);
						if (cache != null) {
							var cacheURI = toURI(cache);
							if (locationURI.equals(cacheURI)
									&& installationLocation.relativize(locationURI) == locationURI) {
								var artifactsXMLFolder = findArtifactsXMLFolder(uri);
								if (artifactsXMLFolder != null) {
									artifactRepositoryURIs.add(artifactsXMLFolder);
									continue;
								}
							}
							if (isExcludedArtifactRepository(locationURI)) {
								continue;
							}
						}
						artifactRepositoryURIs.add(locationURI);
					}
				}
			}
		}

		if (types.contains(IRepository.TYPE_ARTIFACT)) {
			var artifactRepositoryManager = getArtifactRepositoryManager();
			artifactRepositoryManager.loadRepository(uri, progress.split(1));
		}

		monitor.done();
	}

	private void loadSourceRepositories() {
		if (!p2ArtifactSourceRepositoryURIs.isEmpty()) {

			var artifactRepositories = Set
					.of(artifactRepositoryManager.getKnownRepositories(IRepositoryManager.REPOSITORIES_ALL));
			var metadataRepositories = Set
					.of(metadataRepositoryManager.getKnownRepositories(IRepositoryManager.REPOSITORIES_ALL));

			for (var p2ArtifactSourceRepositoryURI : p2ArtifactSourceRepositoryURIs) {
				loadArtifactSource(p2ArtifactSourceRepositoryURI, null, new HashSet<>());
			}

			for (var uri : artifactRepositoryManager.getKnownRepositories(IRepositoryManager.REPOSITORIES_ALL)) {
				if (!artifactRepositories.contains(uri)) {
					artifactRepositoryManager.removeRepository(uri);
				}
			}
			for (var uri : metadataRepositoryManager.getKnownRepositories(IRepositoryManager.REPOSITORIES_ALL)) {
				if (!metadataRepositories.contains(uri)) {
					metadataRepositoryManager.removeRepository(uri);
				}
			}
		}
	}

	private boolean isExcludedArtifactRepository(URI locationURI) {
		try {
			var locationFolder = Path.of(locationURI);
			try {
				// Maybe the cache folder was deleted or maybe just the binary folder in the
				// cache folder.
				if (!Files.isDirectory(locationFolder)) {
					// No folder, so continue.
					return true;
				}
				if (Files.list(locationFolder).filter(Files::isDirectory).filter(directory -> {
					try {
						return !Files.list(directory).findAny().isEmpty();
					} catch (IOException e) {
						return false;
					}
				}).findAny().isEmpty()) {
					// No nested non-empty folders, so there cannot be actual content in the
					// repository.
					return true;
				}
			} catch (IOException e) {
				// Not generally expected listing a folder that exists.
			}
		} catch (IllegalArgumentException | FileSystemNotFoundException ex) {
			// Expected if it's not a file: URI.
		}
		return false;
	}

	private URI findArtifactsXMLFolder(URI uri) {
		for (var path = Path.of(uri).getParent(); path != null; path = path.getParent()) {
			if (Files.isRegularFile(path.resolve("artifacts.xml"))) {
				return toURI(path);
			}
		}
		return null;
	}

	private IInstallableUnit createContextIU(String environments) {
		var properties = Stream.of(environments.split(",")).map(property -> property.split("="))
				.collect(Collectors.toMap(pair -> pair[0], pair -> pair[1]));
		return InstallableUnit.contextIU(properties);
	}

	private void addJRE(IProgressMonitor monitor) throws ProvisionException {
		if (query(QueryUtil.createIUQuery(A_JRE_JAVASE_ID), null).isEmpty()) {
			var jreIU = JREAction.createJREIU();
			try {
				var jres = Files.createTempDirectory("jres");
				jres.toFile().deleteOnExit();
				var jresRepository = metadataRepositoryManager.createRepository(jres.toUri(), "JREs",
						IMetadataRepositoryManager.TYPE_SIMPLE_REPOSITORY, Map.of());
				jresRepository.addInstallableUnits(List.of(jreIU));
				var descriptor = new RepositoryDescriptor();
				descriptor.setKind(RepositoryDescriptor.KIND_METADATA);
				descriptor.setLocation(jresRepository.getLocation());
				addSource(descriptor);
			} catch (IOException e) {
				throw new ProvisionException("Cannot create temp folder: ", e);
			}
		}
	}

	private Collection<IMetadataRepository> gatherSimpleRepositories(Set<IMetadataRepository> visited,
			Map<URI, IMetadataRepository> repositories, IMetadataRepository repository) throws ProvisionException {
		if (visited.add(repository)) {
			if (repository instanceof ICompositeRepository<?> composite) {
				var children = composite.getChildren();
				for (var child : children) {
					var childRepository = getMetadataRepositoryManager().loadRepository(child, null);
					gatherSimpleRepositories(visited, repositories, childRepository);
				}
			} else {
				repositories.put(repository.getLocation(), repository);
			}
		}
		return repositories.values();
	}

	private IArtifactDescriptor createMetadataArtifactDecriptor(IInstallableUnit iu) {
		var artifactRepository = getCompositeArtifactRepository();
		var artifactKey = artifactRepository.createArtifactKey(METADATA_ARTIFACT, iu.getId(), iu.getVersion());
		var artifactDescriptor = (ArtifactDescriptor) artifactRepository.createArtifactDescriptor(artifactKey);
		artifactDescriptor.setRepository(artifactRepository);

		for (var metadataRepository : metadataRepositories) {
			if (metadataRepository.contains(iu)) {
				artifactDescriptor.setProperty("location", metadataRepository.getLocation().toString());
				return artifactDescriptor;
			}
		}

		throw new RuntimeException("Not location for " + iu);
	}

	private void associate(IInstallableUnit iu, IArtifactDescriptor artifactDescriptor) {
		var artifactKey = artifactDescriptor.getArtifactKey();
		artifactIUs.put(artifactKey, iu);
		artifactDescriptors.put(artifactKey, artifactDescriptor);
	}

	private Component createAncestorComponent(Component parent, MavenDescriptor mavenDescriptor) {
		var component = new Component();
		component.setBomRef(parent.getBomRef() + "^");
		component.setType(Component.Type.LIBRARY);
		component.setName(mavenDescriptor.artifactId());
		component.setGroup(mavenDescriptor.groupId());
		component.setVersion(mavenDescriptor.version());
		component.setPurl(mavenDescriptor.mavenPURL());
		return component;
	}

	private Component createMavenJarComponent(Component parent, String path, MavenDescriptor mavenDescriptor,
			byte[] bytes) {
		var component = new Component();
		component.setBomRef(parent.getBomRef() + "^" + path);
		component.setType(Component.Type.LIBRARY);
		if (setMavenPurl(component, mavenDescriptor, bytes)) {
			// If it's verified to be the identical artifact.
			component.setName(mavenDescriptor.artifactId());
			component.setGroup(mavenDescriptor.groupId());
			component.setVersion(mavenDescriptor.version());
		} else {
			// If it's got a pedigree, use the original jar path.
			component.setName(path);
		}
		return component;
	}

	private Component createJarComponent(Component parent, String path) {
		var component = new Component();
		component.setBomRef(parent.getBomRef() + "^" + path);
		component.setType(Component.Type.LIBRARY);
		component.setName(path);
		component.setScope(Scope.REQUIRED);
		return component;
	}

	private Component createComponent(IInstallableUnit iu) {
		var component = new Component();
		component.setName(iu.getId());
		component.setType(Component.Type.LIBRARY);
		component.setVersion(iu.getVersion().toString());
		component.setScope(Scope.REQUIRED);

		var name = iu.getProperty(IInstallableUnit.PROP_NAME, null);
		var description = iu.getProperty(IInstallableUnit.PROP_DESCRIPTION, null);
		if (description != null) {
			// Use ZERO_WIDTH_SPACE as a marker for rendering the description separately
			// from the name.
			component.setDescription(name == null ? "" : name + " - " + ZERO_WIDTH_SPACE + description);
		} else if (name != null) {
			component.setDescription(name);
		}

		var provider = iu.getProperty(IInstallableUnit.PROP_PROVIDER, null);
		if (provider != null) {
			component.setPublisher(provider);
		}

		var docURL = iu.getProperty(IInstallableUnit.PROP_DOC_URL, null);
		if (docURL != null && docURL.startsWith("http")) {
			addExternalReference(component, ExternalReference.Type.WEBSITE, docURL);
		}

		var descriptionURL = iu.getProperty(IInstallableUnit.PROP_DESCRIPTION_URL, null);
		if (descriptionURL != null && descriptionURL.startsWith("http")) {
			addExternalReference(component, ExternalReference.Type.WEBSITE, descriptionURL);
		}

		for (var property : iu.getProperties().entrySet()) {
			var key = property.getKey();
			var value = property.getValue();
			// Filter properties that will be reflected elsewhere in the gathered details,
			// or are not relevant.
			if (!key.startsWith("df_LT") //
					&& !key.endsWith(".pluginName") //
					&& !key.endsWith(".Bundle-Name") //
					&& !key.endsWith(".providerName") //
					&& !key.endsWith(".Bundle-Vendor") //
					&& !key.startsWith("maven-") //
					&& !key.startsWith("iplog.") //
					&& !IInstallableUnit.PROP_NAME.equals(key) //
					&& !"org.eclipse.justj.model".equals(key) //
					&& !"org.eclipse.update.feature.plugin".equals(key) //
					&& !"pgp.trustedPublicKeys".equals(key) //
					&& !"org.eclipse.update.feature.exclusive".equals(key) //
					&& !"org.eclipse.oomph.p2.iu.compatibility".equals(key) //
					&& !MetadataFactory.InstallableUnitDescription.PROP_TYPE_GROUP.equals(key)
					&& !MetadataFactory.InstallableUnitDescription.PROP_TYPE_FRAGMENT.equals(key)
					&& !MetadataFactory.InstallableUnitDescription.PROP_TYPE_PRODUCT.equals(key)
					&& !IInstallableUnit.PROP_BUNDLE_LOCALIZATION.equals(key)
					&& !IInstallableUnit.PROP_DESCRIPTION.equals(key)
					&& !IInstallableUnit.PROP_DESCRIPTION_URL.equals(key) && !IInstallableUnit.PROP_CONTACT.equals(key) //
					&& !IInstallableUnit.PROP_PROVIDER.equals(key)//
					&& !IInstallableUnit.PROP_DOC_URL.equals(key) //
					&& !value.startsWith("%")) {
				component.addProperty(createProperty(key, value));
			}
		}

		var touchpointDetails = getTouchpointDetails(iu);
		if (touchpointDetails != null) {
			// Note that touchpoints are not necessarily only on metadata components.
			component.addProperty(createProperty("touchpoint", touchpointDetails));

			// Also represent this as data since components of type data are generally
			// expected to have data.
			var data = new ComponentData();
			data.setType(ComponentDataType.CONFIGURATION);
			var content = new Content();
			var attachmentText = new AttachmentText();
			attachmentText.setContentType("application/xml");
			attachmentText.setText(touchpointDetails);
			content.setAttachment(attachmentText);
			data.setContents(content);
			component.setData(List.of(data));
		}

		return component;
	}

	private String setBomRef(Component component, IArtifactDescriptor artifactDescriptor) {
		if (isMetadata(artifactDescriptor)) {
			var artifactKey = artifactDescriptor.getArtifactKey();
			component.setBomRef(METADATA_ARTIFACT + "/" + artifactKey.getId() + '_' + artifactKey.getVersion());
		} else {
			var artifactRepository = (SimpleArtifactRepository) artifactDescriptor.getRepository();
			var artifactLocation = artifactRepository.getLocation(artifactDescriptor);
			var location = artifactRepository.getLocation();
			var relativeLocation = location.relativize(artifactLocation);
			component.setBomRef(relativeLocation.toString());
		}
		return component.getBomRef();
	}

	private void setPurl(Component component, IInstallableUnit iu, IArtifactDescriptor artifactDescriptor,
			byte[] bytes) {
		var mavenDescriptor = MavenDescriptor.create(iu, artifactDescriptor, bytes, queryCentral, contentHandler);
		if (mavenDescriptor != null && !mavenDescriptor.isSnapshot()) {
			if (setMavenPurl(component, mavenDescriptor, bytes)) {
				return;
			}
		}

		var artifactKey = artifactDescriptor.getArtifactKey();
		var basicLocation = isMetadata(artifactDescriptor) ? URI.create(artifactDescriptor.getProperty("location"))
				: getArtifactLocation(artifactDescriptor);
		if (strictSourceRepositories) {
			var sourceArtifactDescriptor = ArtifactSourceRepository.getSourceArtifactDescriptor(artifactDescriptor,
					artifactSourceRepositories);
			if (sourceArtifactDescriptor != null) {
				try {
					var uri = sourceArtifactDescriptor.getRepository().getLocation().resolve("./"
							+ artifactKey.getClassifier() + "-" + artifactKey.getId() + "-" + artifactKey.getVersion());
					var sourceBytes = contentHandler.getBinaryContent(uri,
							() -> getArtifactBytes(sourceArtifactDescriptor.getRepository(), sourceArtifactDescriptor));
					if (equivalent(bytes, sourceBytes, new ArrayList<>())) {
						basicLocation = sourceArtifactDescriptor.getRepository().getLocation();
					}
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}

		var location = uriRedirections.redirect(basicLocation);
		var encodedLocation = urlEncodeQueryParameter(location.toString());
		var purl = "pkg:p2/" + artifactKey.getId() + "@" + artifactKey.getVersion() + "?classifier="
				+ artifactKey.getClassifier() + "&repository_url=" + encodedLocation;
		component.setPurl(purl);
	}

	private boolean setMavenPurl(Component component, MavenDescriptor mavenDescriptor, byte[] bytes) {
		try {
			var mavenArtifactBytes = contentHandler.getBinaryContent(mavenDescriptor.toArtifactURI());

			// Call this only if the Maven artifact exists.
			getClearlyDefinedProperty(component, mavenDescriptor);

			// Only if the artifact is byte-for-byte equal do we generate a PURL reference
			// to the Maven artifact.
			var differences = new ArrayList<String>();
			if (equivalent(bytes, mavenArtifactBytes, differences)) {
				var purl = mavenDescriptor.mavenPURL();
				component.setPurl(purl);
				return true;
			}

			// Otherwise record this as a pedigree ancestor component.
			var pedigree = new Pedigree();
			var ancenstors = new Ancestors();
			var ancestorComponent = createAncestorComponent(component, mavenDescriptor);
			gatherLicenses(ancestorComponent, mavenDescriptor, null, mavenArtifactBytes);
			addHashes(ancestorComponent, mavenArtifactBytes);
			ancenstors.addComponent(ancestorComponent);
			pedigree.setAncestors(ancenstors);
			pedigree.setNotes(String.join(", ", differences));
			component.setPedigree(pedigree);
		} catch (ContentHandler.ContentHandlerException e) {
			// The only valid reason to fail is a 404,
			// i.e., resource does not exist on Maven Central.
			if (e.statusCode() != 404) {
				throw new RuntimeException(e);
			}
		} catch (NoSuchFileException e) {
			// The only valid reason to fail, like a 404,
			// i.e., resource does not exist on the file system.
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		return false;
	}

	private boolean equivalent(byte[] bytes1, byte[] bytes2, List<String> differences) {
		try {
			return Arrays.equals(bytes1, bytes2) || zipEquals(bytes1, bytes2, differences);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private boolean zipEquals(byte[] bytes1, byte[] bytes2, List<String> differences) throws IOException {
		return equals(getZipContents(bytes1), getZipContents(bytes2), differences);
	}

	private boolean equals(Map<String, byte[]> zip1, Map<String, byte[]> zip2, List<String> differences) {
		for (var key : zip1.keySet()) {
			if (!zip2.containsKey(key)) {
				differences.add("Added " + key);
			}
		}
		for (var key : zip2.keySet()) {
			if (!zip1.containsKey(key)) {
				differences.add("Removed " + key);
			}
		}
		for (var entry : zip1.entrySet()) {
			var key = entry.getKey();
			var bytes2 = zip2.get(key);
			if (bytes2 != null) {
				if (!Arrays.equals(entry.getValue(), bytes2)) {
					differences.add("Modified " + key);
				}
			}
		}
		return differences.isEmpty();
	}

	private URI getArtifactLocation(IArtifactDescriptor artifactDescriptor) {
		// First see if there are any explicitly configured source repositories.
		if (!strictSourceRepositories && !p2ArtifactSourceRepositoryURIs.isEmpty()) {
			for (var repository : artifactSourceRepositories) {
				if (repository.contains(artifactDescriptor)) {
					return repository.uri();
				}
			}
		}
		// If not, use where we have fetched this from.
		return artifactDescriptor.getRepository().getLocation();
	}

	private void getClearlyDefinedProperty(Component component, MavenDescriptor mavenDescriptor) {
		if (!fetchClearlyDefined) {
			return;
		}
		if (!"sources".equals(mavenDescriptor.classifier())) {
			var clearlyDefinedURI = mavenDescriptor.toClearlyDefinedURI();
			try {
				var clearlyDefinedContent = contentHandler.getContent(clearlyDefinedURI);
				try {
					var clearlyDefinedJSON = new JSONObject(clearlyDefinedContent);
					var clearlyDefinedLicensed = clearlyDefinedJSON.getJSONObject("licensed");
					if (clearlyDefinedLicensed.has("declared")) {
						var clearlyDefinedDeclaredLicense = clearlyDefinedLicensed.get("declared");
						if (clearlyDefinedDeclaredLicense instanceof String value) {
							component.addProperty(createProperty("clearly-defined", value));
						}
					}
				} catch (RuntimeException ex) {
					System.err.println("Bad ClearlyDefined content: " + clearlyDefinedURI);
				}
			} catch (IOException ex) {
				throw new RuntimeException(ex);
			}
		}
	}

	private byte[] getArtifactContent(Component component, IArtifactDescriptor artifactDescriptor) {
		var isMetadata = isMetadata(artifactDescriptor);
		byte[] bytes;
		if (isMetadata) {
			bytes = new byte[0];
			component.setType(Type.DATA);
		} else {
			// Only a component of type data should have data.
			component.setData(List.of());
			bytes = getArtifactBytes(getCompositeArtifactRepository(), artifactDescriptor);
			addHashes(component, bytes);
		}
		return bytes;
	}

	private byte[] getArtifactBytes(IArtifactRepository repository, IArtifactDescriptor artifactDescriptor) {
		var artifactDescriptorRepository = artifactDescriptor.getRepository();
		if (artifactDescriptorRepository instanceof SimpleArtifactRepository simpleArtifactRepository) {
			var location = simpleArtifactRepository.getLocation(artifactDescriptor);
			if (location != null && !"file".equals(location.getScheme())) {
				try {
					return contentHandler.getBinaryContent(location,
							() -> basicGetArtifactBytes(repository, artifactDescriptor));
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}
		return basicGetArtifactBytes(repository, artifactDescriptor);
	}

	private byte[] basicGetArtifactBytes(IArtifactRepository repository, IArtifactDescriptor artifactDescriptor) {
		for (var retry = 0;; ++retry) {
			var out = new ByteArrayOutputStream();
			var status = repository.getRawArtifact(artifactDescriptor, out, new NullProgressMonitor());
			if (retry < 5 && status.getCode() == IArtifactRepository.CODE_RETRY) {
				continue;
			}
			if (!status.isOK()) {
				throw new RuntimeException(new CoreException(status));
			}
			return out.toByteArray();
		}
	}

	private void gatherLicenses(Component component, MavenDescriptor mavenDescriptor, IInstallableUnit iu,
			byte[] bytes) {
		var licenseToName = new TreeMap<String, String>();
		if (bytes.length > 2 && bytes[0] == 0x50 && bytes[1] == 0x4B) {
			gatherComponentDetailsFromJar(component, bytes, licenseToName);
		}

		if (mavenDescriptor != null && !mavenDescriptor.isSnapshot()) {
			try {
				var content = contentHandler.getContent(mavenDescriptor.toPOMURI());
				gatherInformationFromPOM(component, content.getBytes(StandardCharsets.UTF_8), licenseToName);
			} catch (ContentHandler.ContentHandlerException e) {
				if (e.statusCode() != 404) {
					throw new RuntimeException(e);
				}
			} catch (NoSuchFileException e) {
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		if (iu != null) {
			var licenses = iu.getLicenses(null);
			for (var license : licenses) {
				var location = license.getLocation();
				if (location != null) {
					var value = location.toString();
					if (!value.startsWith("%")) {
						addLicense(licenseToName, value, null);
					}
				}
			}
		}

		if (licenseToName.isEmpty()) {
			gatherKnownLicenses(component, iu, licenseToName);
		}

		if (!licenseToName.isEmpty()) {
			var licenseChoice = new LicenseChoice();
			for (var licenseEntry : licenseToName.entrySet()) {
				var licenseName = licenseEntry.getValue();
				var url = licenseEntry.getKey();
				var license = new License();
				if (licenseName != null) {
					if (spdxIndex.isValidID(licenseName)) {
						license.setId(licenseName);
					} else {
						license.setName(licenseName);
					}
				} else {
					license.setName("indeterminate");
				}
				license.setUrl(url);
				licenseChoice.addLicense(license);
			}
			component.setLicenses(licenseChoice);
		}
	}

	private void gatherKnownLicenses(Component component, IInstallableUnit iu, Map<String, String> licenseToName) {
		var bomRef = component.getBomRef();
		for (var entry : COMPONENT_LICENSE_MAPPINGS) {
			if (entry.getKey().matcher(bomRef).matches()) {
				var spdxID = entry.getValue();
				if (!spdxID.isEmpty()) {
					addSPDXLicense(licenseToName, spdxID);
				}
				return;
			}
		}
	}

	private void gatherComponentDetailsFromJar(Component component, byte[] bytes, Map<String, String> licenseToName) {
		try (var zip = new ZipInputStream(new ByteArrayInputStream(bytes))) {
			ZipEntry entry;
			while ((entry = zip.getNextEntry()) != null) {
				var name = entry.getName();
				if ("META-INF/MANIFEST.MF".equals(name)) {
					var allBytes = zip.readAllBytes();
					// String contents = new String(allBytes, StandardCharsets.UTF_8);
					var headers = ManifestElement.parseBundleManifest(new ByteArrayInputStream(allBytes));

					var bundleLicense = headers.get("Bundle-License");
					if ("Eclipse Public License v2.0".equals(bundleLicense)
							|| "Eclipse Public License, Version 2.0;link=\"http://www.eclipse.org/legal/epl-2.0\""
									.equals(bundleLicense)) {
						addSPDXLicense(licenseToName, "EPL-2.0");
					} else if ("Eclipse Public License v1.0".equals(bundleLicense)) {
						addSPDXLicense(licenseToName, "EPL-1.0");
					} else if ("The Apache License, Version 2.0".equals(bundleLicense)
							|| "Apache License, Version 2.0; see: http://www.apache.org/licenses/LICENSE-2.0.txt"
									.equals(bundleLicense)) {
						addSPDXLicense(licenseToName, "Apache-2.0");
					} else if (bundleLicense != null) {
						var bundleLicenseElements = ManifestElement.parseHeader("Bundle-License", bundleLicense);
						for (var bundleLicenseElement : bundleLicenseElements) {
							var value = bundleLicenseElement.getValue();
							var linkAttribute = bundleLicenseElement.getAttribute("link");
							if (linkAttribute != null) {
								var links = linkAttribute.split(" *, *");
								for (var link : links) {
									addLicense(licenseToName, link, value);
								}
							} else {
								if (value.startsWith("://")) {
									value = "https" + value;
								} else if ("jquery.com/license/".equals(value) || "jquery.org/license".equals(value)) {
									value = "https://" + value;
								}
								if (!value.startsWith("http")) {
									var license = spdxIndex.getLicense(value);
									if (license != null) {
										addLicense(licenseToName, license, value);
									} else {
										System.err.println("license=" + value);
									}
								} else {
									addLicense(licenseToName, value, null);
								}
							}
						}
					}

					var bundleDoc = headers.get("Bundle-DocURL");
					if (bundleDoc != null && bundleDoc.startsWith("http")) {
						addExternalReference(component, ExternalReference.Type.WEBSITE, bundleDoc);
					}

					var bundleSCM = headers.get("Bundle-SCM");
					if (bundleSCM != null) {
						var bundleSCMElements = ManifestElement.parseHeader("Bundle-SCM", bundleSCM);
						var connection = "";
						var tag = "";
						for (var bundleSCMElement : bundleSCMElements) {
							var parts = bundleSCMElement.getValue().split("=");
							if (parts.length == 2) {
								if ("connection".equals(parts[0])) {
									connection = parts[1].replace("\"", "");
								} else if ("tag".equals(parts[0])) {
									tag = parts[1].replace("\"", "");
								}
							}
						}
						if (!connection.isEmpty()) {
							addExternalReference(component, ExternalReference.Type.VCS,
									connection + (tag.isEmpty() ? "" : "?tag=" + tag));
							addGitHubIssues(component, connection);
						}
					}

					var eclipseSourceReferences = headers.get("Eclipse-SourceReferences");
					if (eclipseSourceReferences != null) {
						var eclipseSourceReferenceElements = ManifestElement.parseHeader("Eclipse-SourceReferences",
								eclipseSourceReferences);
						for (var eclipseSourceReferenceElement : eclipseSourceReferenceElements) {
							var value = eclipseSourceReferenceElement.getValue();
							var query = Collections.list(eclipseSourceReferenceElement.getKeys()).stream()
									.map(key -> (key + '='
											+ urlEncodeQueryParameter(eclipseSourceReferenceElement.getAttribute(key))))
									.collect(Collectors.joining("&", "?", ""));
							addExternalReference(component, ExternalReference.Type.VCS, value + query);
							addGitHubIssues(component, value);
						}
					}

					var bundleVersion = headers.get("Bundle-Version");
					if (bundleVersion != null && !Objects.equals(bundleVersion, component.getVersion())) {
						component.setVersion(bundleVersion);
					}
				} else if (MAVEN_POM_PATTERN.matcher(name).matches()) {
					var allBytes = zip.readAllBytes();
					gatherInformationFromPOM(component, allBytes, licenseToName);
				} else if ("about.html".equals(name)) {
					var allBytes = zip.readAllBytes();
					gatherLicensesFromAbout(component, allBytes, licenseToName);
				} else if (EDL_10_NAME_PATTERN.matcher(name).matches()) {
					// https://lists.spdx.org/g/Spdx-legal/topic/request_for_adding_eclipse/67981884
					addSPDXLicense(licenseToName, "BSD-3-Clause");
				} else if (EPL_20_NAME_PATTERN.matcher(name).matches()) {
					addSPDXLicense(licenseToName, "EPL-2.0");
				} else if (EPL_10_NAME_PATTERN.matcher(name).matches()) {
					addSPDXLicense(licenseToName, "EPL-1.0");
				} else if (META_INF_FILE_PATTERN.matcher(name).matches()) {
					if (!name.endsWith(".RSA") && !name.endsWith(".SF") && !name.endsWith(".inf")
							&& !name.endsWith(".DSA") && !name.endsWith("DEPENDENCIES")) {
						var allBytes = zip.readAllBytes();
						gatherLicensesFromFile(allBytes, licenseToName);
					}
				} else if (BUNDLE_PROPERTIES_PATTERN.matcher(name).matches()) {
					var allBytes = zip.readAllBytes();
					gatherLicensesFromFile(allBytes, licenseToName);
				} else if (LICENSE_FILE_PATTERN.matcher(name).matches()) {
					var allBytes = zip.readAllBytes();
					gatherLicensesFromFile(allBytes, licenseToName);
				}
				zip.closeEntry();
			}
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	private void addGitHubIssues(Component component, String value) {
		if (!gitIssues) {
			return;
		}
		var matcher = GITHUB_SCM_PATTERN.matcher(value);
		if (matcher.matches()) {
			var uri = URI.create("https://github.com/" + matcher.group("repo") + "/issues");
			if (contentHandler.exists(uri)) {
				addExternalReference(component, ExternalReference.Type.ISSUE_TRACKER, uri.toString());
			}
		}
	}

	private void gatherLicensesFromFile(byte[] bytes, Map<String, String> licenseToName) {
		var content = new String(bytes, StandardCharsets.UTF_8);
		if (APACHE_PUBLIC_LICENSE_20_PATTERN.matcher(content).find()) {
			addSPDXLicense(licenseToName, "Apache-2.0");
		} else if (GPL_21_PATTERN.matcher(content).find()) {
			addSPDXLicense(licenseToName, "LGPL-2.1-only");
		} else if (content.contains("The Apache Software License, Version 1.1")) {
			addSPDXLicense(licenseToName, "Apache-1.1");
		} else if (content.startsWith("BSD License")) {
			addSPDXLicense(licenseToName, "0BSD");
		} else if (content.startsWith("# Eclipse Public License - v 2.0")
				|| content.startsWith("Eclipse Public License - v 2.0")) {
			addSPDXLicense(licenseToName, "EPL-2.0");
		} else if (content.contains("IBM Public License Version 1.0")) {
			addSPDXLicense(licenseToName, "IPL-1.0");
		} else {
			// SPDX-License-Identifier: BSD-3-Clause
			var matcher = SPDX_ID_PATTERN.matcher(content);
			if (matcher.find()) {
				do {
					var spdxId = matcher.group(1).trim();
					var license = spdxIndex.getLicense(spdxId);
					if (license != null) {
						addLicense(licenseToName, license, spdxId);
					} else {
						var parts = spdxId.replaceAll("[()]", "")
								.split("\\s+OR\\s+|\\s+AND\\s+|\\s+WITH\\s+|\\s+with\\s+");
						if (parts.length > 1) {
							for (var part : parts) {
								license = spdxIndex.getLicense(part);
								if (license != null) {
									addLicense(licenseToName, license, spdxId);
								} else {
									System.err.println("license-part='" + part + "'");
								}
							}
						} else {
							System.err.println("license-part='" + spdxId + "'");
						}
					}
				} while (matcher.find());
			} else {
				// System.err.println("###");
			}
		}
	}

	private boolean isAcceptedLicense(String url) {
		if (allLicenses.contains(url)) {
			return true;
		}
		return ACCEPTED_LICENSE_URL_PATTERN.matcher(url).matches();
	}

	private boolean isIgnoredLicense(String url) {
		if (ignoredLicense.contains(url) || rejectedLicense.contains(url)) {
			return true;
		}
		return IGNORED_LICENSE_URL_PATTERN.matcher(url).matches();
	}

	private void gatherLicensesFromAbout(Component component, byte[] bytes, Map<String, String> licenseToName) {
		var content = new String(bytes, StandardCharsets.UTF_8);
		var urls = new LinkedHashSet<String>();
		for (var matcher = POTENTIAL_LICENSE_REFERENCE_PATTERN.matcher(content); matcher.find();) {
			var url = "https://" + matcher.group(1);
			if (urls.contains(url)) {
				continue;
			}

			if (isAcceptedLicense(url)) {
				urls.add(url);
			} else if (!isIgnoredLicense(url)) {
				rejectedLicense.add(url);
			}
		}

		for (var url : urls) {
			addLicense(licenseToName, url, null);
		}

		if (content.contains("Eclipse Distribution License - v 1.0")
				|| content.contains("Eclipse Distribution License - Version 1.0")) {
			addSPDXLicense(licenseToName, "BSD-3-Clause");
		} else if (content.contains("Eclipse Public License Version 2.0")) {
			addSPDXLicense(licenseToName, "EPL-2.0");
		}
	}

	private void addSPDXLicense(Map<String, String> licenseToName, String id) {
		var license = spdxIndex.getLicense(id);
		addLicense(licenseToName, license, id);
	}

	private void addLicense(Map<String, String> licenseToName, String url, String name) {
		var license = url.replaceAll("^http://", "https://");
		if ("xhttps://glassfish.dev.java.net/nonav/public/CDDL+GPL.html".equals(license)) {
			System.err.println(url);
		}

		for (var entry : URL_LICENSE_MAPPINGS) {
			if (entry.getKey().matcher(license).matches()) {
				var spdxID = entry.getValue();
				if (!spdxID.isEmpty()) {
					var spdxLicense = spdxIndex.getLicense(spdxID);
					allLicenses.add(spdxLicense);
					licenseToName.put(spdxLicense, spdxID);
				}
				return;
			}
		}

		allLicenses.add(license);
		licenseToName.put(license, name);
		var old = licenseToName.put(license, null);
		if (old != null) {
			licenseToName.put(license, old);
		}
	}

	private void gatherInformationFromPOM(Component component, byte[] bytes, Map<String, String> licenseToName) {
		try {
			var builder = newDocumentBuilder();
			var document = builder.parse(new InputSource(new ByteArrayInputStream(bytes)));
			gatherInformationFromPOM(component, document, licenseToName);
		} catch (RuntimeException ex) {
			throw ex;
		} catch (ParserConfigurationException | SAXException | IOException ex) {
			throw new RuntimeException(ex);
		}
	}

	private void gatherInformationFromPOM(Component component, Document document, Map<String, String> licenseToName) {
		var licenses = evaluate(document, "//pom:license|//license");
		if (!licenses.isEmpty()) {
			for (var element : licenses) {
				var name = getText(element, "name");
				var url = getText(element, "url");
				if (url == null) {
					if (name == null) {
						continue;
					}
					var spdxLicense = spdxIndex.getLicense(name);
					if (spdxLicense == null) {
						spdxLicense = name;
					}
					url = spdxLicense;
				}

				if (!url.startsWith("http")) {
					continue;
				}

				var parts = url.split(" *, *");
				for (var part : parts) {
					if (part.startsWith("://")) {
						part = "https" + part;
					}
					addLicense(licenseToName, part, name);
				}
			}
		}

		var scms = evaluate(document, "//pom:scm|//scm");
		for (var element : scms) {
			var connection = getText(element, "connection");
			if (connection == null) {
				connection = getText(element, "developerConnection");
				if (connection == null) {
					connection = getText(element, "url");
				}
			}
			if (connection != null) {
				addExternalReference(component, ExternalReference.Type.VCS, connection);
			}
		}

		var issues = evaluate(document, "//pom:issueManagement|//issueManagement");
		for (var element : issues) {
			var url = getText(element, "url");
			if (url != null) {
				addExternalReference(component, ExternalReference.Type.ISSUE_TRACKER, url);
			}
		}

		var websites = evaluate(document, "//pom:project|//project");
		for (var element : websites) {
			var url = getText(element, "url");
			if (url != null && url.startsWith("http")) {
				addExternalReference(component, ExternalReference.Type.WEBSITE, url);
			}
		}

		var mailingLists = evaluate(document, "//pom:mailingList|//mailingList");
		for (var element : mailingLists) {
			var url = getText(element, "archive");
			if (url == null) {
				url = getText(element, "post");
			}
			if (url != null) {
				addExternalReference(component, ExternalReference.Type.MAILING_LIST, url);
			} else {
				System.err.println("##");
			}
		}

		var distributions = evaluate(document, "//pom:repository|//repository");
		for (var element : distributions) {
			if (element.getParentNode().getLocalName().equals("distributionManagement")) {
				var url = getText(element, "url");
				if (url != null) {
					addExternalReference(component, ExternalReference.Type.DISTRIBUTION, url);
				} else {
					System.err.println("##");
				}
			}
		}
	}

	/**
	 * Query OSV (Open Source Vulnerabilities) database for vulnerability
	 * information and populate the component with any found vulnerabilities.
	 *
	 * @param component      the component to populate with vulnerability
	 *                       information
	 * @param contentHandler the content handler for querying
	 * @throws InterruptedException
	 * @throws IOException
	 */
	private void queryOSV(Component component, ContentHandler contentHandler) throws IOException, InterruptedException {
		var purl = component.getPurl();
		if (purl == null) {
			return;
		}
		var queryJson = String.format("{\"package\":{\"purl\":\"%s\"}}", purl);
		var body = contentHandler.getPostContent(OSV_URI, List.of("Content-Type", "application/json"), queryJson);
		var jsonResponse = new JSONObject(body);
		if (jsonResponse.has("vulns")) {
			var vulns = jsonResponse.getJSONArray("vulns");
			for (var i = 0; i < vulns.length(); i++) {
				var vulnObj = vulns.getJSONObject(i);
				if (vulnObj.has("references")) {
					var references = vulnObj.getJSONArray("references");
					for (var j = 0; j < references.length(); j++) {
						var ref = references.getJSONObject(j);
						if (ref.has("url") && ref.has("type")) {
							var type = ref.getString("type");
							var reference = new ExternalReference();
							reference.setUrl(ref.getString("url"));
							if ("ADVISORY".equals(type)) {
								reference.setType(ExternalReference.Type.ADVISORIES);
							} else if ("WEB".equals(type)) {
								reference.setType(ExternalReference.Type.WEBSITE);
							} else if ("PACKAGE".equals(type)) {
								reference.setType(ExternalReference.Type.VCS);
							} else {
								reference.setType(ExternalReference.Type.OTHER);
							}
							component.addExternalReference(reference);
						}
					}
				}
			}
		}
	}

	private boolean isExcluded(IRequirement requirement) {
		if (requirement instanceof IRequiredCapability requiredCapability) {
			var namespace = requiredCapability.getNamespace();
			if (PublisherHelper.NAMESPACE_ECLIPSE_TYPE.equals(namespace)) {
				return true;
			}
		}
		return false;
	}

	private boolean isExpectedMissingArtifact(IInstallableUnit iu) {
		var value = iu.getId() + ":" + iu.getVersion();
		for (var expectedMissingArtifactIUPattern : expectedMissingArtifactIUPatterns) {
			if (expectedMissingArtifactIUPattern.matcher(value).matches()) {
				return true;
			}
		}
		return false;
	}

	private void resolveDependencies(Dependency dependency, IInstallableUnit iu, boolean processDependencyIUs) {
		var component = getComponent(iu);
		var componentBomRef = component.getBomRef();

		var featureGroupIU = featureJarsToFeatures.get(iu);
		for (var requirement : (featureGroupIU == null ? iu : featureGroupIU).getRequirements()) {
			if (isExcluded(requirement)) {
				continue;
			}

			var matches = requirement.getMatches();
			var requiredIUs = query(QueryUtil.createMatchQuery(matches), null).toSet();
			if (!dependencyIUs.containsAll(requiredIUs)) {
				// Consider the dependency IUs only if there are no non-dependency IUs that
				// satisfy
				// the requirement.
				requiredIUs.removeAll(dependencyIUs);
			}

			if (requiredIUs.isEmpty()) {
				var min = requirement.getMin();
				if (min != 0) {
					var filter = requirement.getFilter();
					if (filter != null) {
						if (!inclusiveContextIUs.isEmpty()
								&& inclusiveContextIUs.stream().noneMatch(contextIU -> filter.isMatch(contextIU))) {
							continue;
						}
						if (!exclusiveContextIUs.isEmpty()
								&& exclusiveContextIUs.stream().anyMatch(contextIU -> filter.isMatch(contextIU))) {
							continue;
						}
					}
					component.addProperty(createProperty("unsatisfied-requirement", requirement.toString()));
				}
			} else {
				for (var requiredIU : requiredIUs) {
					var requiredComponent = getComponent(requiredIU);
					if (requiredComponent == null) {
						if (!requiredIU.getId().startsWith(A_JRE_JAVASE_ID)) {
							if (verbose) {
								System.out.println("requirement-not-mapped-to-artifact=" + requiredIU);
							}
						}
					} else if (!excludedComponents.contains(requiredComponent.getBomRef())) {
						var bomRef = requiredComponent.getBomRef();
						if (!componentBomRef.equals(bomRef)) {
							if (processDependencyIUs) {
								// During the second phase when processing the dependency IUs, only add
								// a dependency to a dependency IU if it is used.
								if (!dependencyIUs.contains(iu) || usedDependencyIUs.contains(iu)) {
									dependency.addDependency(new Dependency(bomRef));
								}
							} else {
								// During the first phase, keep track of any requirements on dependencies IUs so
								// we can further analyze those during the second phase.
								if (dependencyIUs.contains(requiredIU)) {
									var featureJarIU = featuresToFeatureJars.get(requiredIU);
									usedDependencyIUs.add(featureJarIU == null ? requiredIU : featureJarIU);
								}
								dependency.addDependency(new Dependency(bomRef));
							}
						}
					}
				}
			}
		}
	}

	private Component getComponent(IInstallableUnit iu) {
		var featureJar = featuresToFeatureJars.get(iu);
		return iuComponents.get(featureJar == null ? iu : featureJar);
	}

	private void transferDetailsFromBinaryToSource(Component component, IInstallableUnit iu) {
		var id = iu.getId();
		var matcher = SOURCE_IU_PATTERN.matcher(id);
		if (matcher.matches()) {
			var description = new InstallableUnitDescription();
			description.setId(matcher.group(1) + matcher.group(2));
			description.setVersion(iu.getVersion());
			var binaryIU = MetadataFactory.createInstallableUnit(description);
			var binaryComponent = getComponent(binaryIU);
			if (binaryComponent != null) {
				var licenseChoice = component.getLicenses();
				if (licenseChoice == null) {
					component.setLicenses(binaryComponent.getLicenses());
				}
				var externalReferences = component.getExternalReferences();
				if (externalReferences == null || externalReferences.isEmpty()) {
					component.setExternalReferences(binaryComponent.getExternalReferences());
				}
			} else if (!isExpectedMissingArtifact(iu)) {
				System.err.println("## Missing binary: " + id);
			}
		}
	}

	private void generateXML(Bom bom) {
		if (xml || xmlOutput != null) {
			try {
				var xmlGenerator = createBomXMLGenerator(Version.VERSION_16, bom);
				var xmlString = xmlGenerator.toXmlString();
				if (xml) {
					System.out.println(xmlString);
				}
				if (xmlOutput != null) {
					var output = Path.of(xmlOutput).toAbsolutePath();
					outputs.add(output);
					Files.createDirectories(output.getParent());
					Files.writeString(output, xmlString);
				}
			} catch (Exception ex) {
				throw new RuntimeException(ex);
			}
		}
	}

	private static String getTouchpointDetails(IInstallableUnit iu) {
		var touchpointType = iu.getTouchpointType();
		if (ITouchpointType.NONE.equals(touchpointType)) {
			return null;
		}
		var touchpointData = new ArrayList<>(iu.getTouchpointData());
		if (PublisherHelper.TOUCHPOINT_NATIVE.equals(touchpointType) && touchpointData.isEmpty()) {
			return null;
		}
		if (PublisherHelper.TOUCHPOINT_OSGI.equals(touchpointType)) {
			var filteredTouchpointData = new ArrayList<ITouchpointData>();
			for (var touchpointDataItem : touchpointData) {
				var filteredInstructions = new LinkedHashMap<String, ITouchpointInstruction>();
				var instructions = touchpointDataItem.getInstructions();
				for (var instruction : instructions.entrySet()) {
					var key = instruction.getKey();
					// The 'manifest' is used noise that I've now removed from the p2 publisher.
					// The 'zipped' is just a boolean to indicate that the artifact should be
					// unzipped.
					if ("manifest".equals(key) || "zipped".equals(key)) {
						continue;
					}
					filteredInstructions.put(key, instruction.getValue());
				}
				if (filteredInstructions.isEmpty()) {
					continue;
				}

				filteredTouchpointData.add(MetadataFactory.createTouchpointData(filteredInstructions));
			}

			if (filteredTouchpointData.isEmpty()) {
				return null;
			}

			touchpointData.clear();
			touchpointData.addAll(filteredTouchpointData);
		}

		var out = new ByteArrayOutputStream();
		new MetadataWriter(out, null) {
			@Override
			protected void writeInstallableUnit(IInstallableUnit resolvedIU) {
				start(INSTALLABLE_UNIT_ELEMENT);
				writeTouchpointType(touchpointType);
				writeTouchpointData(touchpointData);
				end(INSTALLABLE_UNIT_ELEMENT);
				flush();
			}

			@Override
			public void cdata(String data, boolean escape) {
				var parts = data.split(";");
				for (var part : parts) {
					super.cdata(part + ";", escape);
				}
			}

			@Override
			public void attribute(String name, int value) {
				if (!"size".equals(name)) {
					super.attribute(name, value);
				}
			}
		}.writeInstallableUnit(iu);
		return new String(out.toByteArray(), StandardCharsets.UTF_8).replaceAll("<\\?.*?\\?>", "").trim().replace("\r",
				"");
	}

	private void generateJson(Bom bom) {
		if (json || jsonOutput != null) {
			var undoables = new ArrayList<Runnable>();
			try {
				// The json serialization of a property value collapses whitespace, including
				// line separators into a single space.
				var components = bom.getComponents();
				if (components != null) {
					for (var component : components) {
						var properties = component.getProperties();
						if (properties != null) {
							for (var property : properties) {
								var value = property.getValue();
								var matcher = TOUCHPOINT_FORMATTTING_PATTERN.matcher(value);
								if (matcher.find()) {
									var jsonValue = new StringBuilder();
									do {
										matcher.appendReplacement(jsonValue,
												"&#x0A;" + matcher.group(1).replaceAll(" ", "&#x20;"));
									} while (matcher.find());
									matcher.appendTail(jsonValue);
									property.setValue(jsonValue.toString());
									undoables.add(() -> property.setValue(value));
								}
							}
						}

						var data = component.getData();
						if (data != null) {
							for (var componentData : component.getData()) {
								var contents = componentData.getContents();
								if (contents != null) {
									var attachmentText = contents.getAttachment();
									if (attachmentText != null
											&& "application/xml".equals(attachmentText.getContentType())) {
										var text = attachmentText.getText();
										if (text != null) {
											var matcher = TOUCHPOINT_FORMATTTING_PATTERN.matcher(text);
											if (matcher.find()) {
												var jsonValue = new StringBuilder();
												do {
													matcher.appendReplacement(jsonValue,
															"&#x0A;" + matcher.group(1).replaceAll(" ", "&#x20;"));
												} while (matcher.find());
												matcher.appendTail(jsonValue);
												attachmentText.setText(jsonValue.toString());
												undoables.add(() -> attachmentText.setText(text));
											}
										}
									}
								}
							}
						}
					}
				}
				var jsonGenerator = BomGeneratorFactory.createJson(Version.VERSION_16, bom);
				var jsonString = jsonGenerator.toJsonString();
				if (json) {
					System.out.println(jsonString);
				}
				if (jsonOutput != null) {
					var output = Path.of(jsonOutput).toAbsolutePath();
					outputs.add(output);
					Files.createDirectories(output.getParent());
					Files.writeString(output, jsonString);
				}
			} catch (Exception ex) {
				throw new RuntimeException(ex);
			} finally {
				undoables.forEach(Runnable::run);
			}
		}
	}

	private static IProvisioningAgent createAgent() throws IOException {
		var defaultAgentProvider = new DefaultAgentProvider();
		defaultAgentProvider.activate(FrameworkUtil.getBundle(IProvisioningAgent.class).getBundleContext());
		var agentTempDirectory = Files.createTempDirectory("sbom-");
		agentTempDirectory.toFile().deleteOnExit();
		return defaultAgentProvider.createAgent(agentTempDirectory.toUri());
	}

	public static record Result(List<String> arguments, List<URI> inputs, List<Path> outputs) {
		public Result(SBOMGenerator sbomGenerator) {
			this(sbomGenerator.getCommandLineArguments(), sbomGenerator.getInputs(), sbomGenerator.getOutputs());
		}
	}

	private static final record ArtifactSourceRepository(URI uri, IArtifactRepository repository) {

		public static IArtifactDescriptor getSourceArtifactDescriptor(IArtifactDescriptor artifactDescriptor,
				Collection<? extends ArtifactSourceRepository> repositories) {
			if (repositories != null) {
				for (var repository : repositories) {
					var sourceArtifactDescriptor = repository.getSourceArtifactDescriptor(artifactDescriptor);
					if (sourceArtifactDescriptor != null) {
						return sourceArtifactDescriptor;
					}
				}
			}
			return null;
		}

		public IArtifactDescriptor getSourceArtifactDescriptor(IArtifactDescriptor otherDescriptor) {
			var descriptors = repository.getArtifactDescriptors(otherDescriptor.getArtifactKey());
			return descriptors.length == 0 ? null : descriptors[0];
		}

		public boolean contains(IArtifactDescriptor otherDescriptor) {
			var descriptors = repository.getArtifactDescriptors(otherDescriptor.getArtifactKey());
			if (descriptors.length > 0) {
				var otherProperties = otherDescriptor.getProperties();
				for (var descriptor : descriptors) {
					var thisProperties = descriptor.getProperties();
					// we want at least one checksum to match!
					if (thisProperties.keySet().stream().filter(key -> key.startsWith("download.checksum."))
							.anyMatch(key -> Objects.equals(thisProperties.get(key), otherProperties.get(key)))) {
						return true;
					}
					// not so good but better than nothing, if size is equal... e.g for local
					// artifacts we only have size as P2 do not store more properties sadly
					if (Objects.equals(thisProperties.get("download.size"), otherProperties.get("download.size"))) {
						return true;
					}
				}
			}
			return false;
		}
	}

	@Override
	public void addSource(RepositoryDescriptor repo) {
		// Force the list to be recomputed to include the addition.
		sourceMetataRepositories.clear();
		super.addSource(repo);
	}
}