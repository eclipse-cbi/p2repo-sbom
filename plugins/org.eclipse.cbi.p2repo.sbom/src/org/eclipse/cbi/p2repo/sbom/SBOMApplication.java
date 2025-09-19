/**
 * Copyright (c) 2023 Eclipse contributors and others.
 *
 * This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.eclipse.cbi.p2repo.sbom;

import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.ArgumentUtil.getArgument;
import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.ArgumentUtil.getArguments;
import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.BOMUtil.addExternalReference;
import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.BOMUtil.computeHash;
import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.BOMUtil.createBomXMLGenerator;
import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.BOMUtil.createProperty;
import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.BOMUtil.urlEncodeQueryParameter;
import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.IOUtil.extractInstallation;
import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.URIUtil.toURI;
import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.XMLUtil.evaluate;
import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.XMLUtil.getText;
import static org.eclipse.cbi.p2repo.sbom.SBOMApplication.XMLUtil.newDocumentBuilder;

import java.awt.Desktop;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
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
import java.util.jar.JarInputStream;
import java.util.regex.Pattern;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.cyclonedx.Version;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.generators.xml.BomXmlGenerator;
import org.cyclonedx.model.Ancestors;
import org.cyclonedx.model.Annotation;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Component.Scope;
import org.cyclonedx.model.Component.Type;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.License;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.Pedigree;
import org.cyclonedx.model.Property;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.MultiStatus;
import org.eclipse.core.runtime.NullProgressMonitor;
import org.eclipse.core.runtime.Status;
import org.eclipse.equinox.app.IApplication;
import org.eclipse.equinox.app.IApplicationContext;
import org.eclipse.equinox.internal.p2.artifact.repository.simple.SimpleArtifactRepository;
import org.eclipse.equinox.internal.p2.metadata.IRequiredCapability;
import org.eclipse.equinox.internal.p2.metadata.InstallableUnit;
import org.eclipse.equinox.internal.p2.metadata.repository.io.MetadataWriter;
import org.eclipse.equinox.p2.core.IAgentLocation;
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
import org.eclipse.equinox.p2.query.QueryUtil;
import org.eclipse.equinox.p2.repository.ICompositeRepository;
import org.eclipse.equinox.p2.repository.IRepository;
import org.eclipse.equinox.p2.repository.IRepositoryManager;
import org.eclipse.equinox.p2.repository.artifact.IArtifactDescriptor;
import org.eclipse.equinox.p2.repository.artifact.IArtifactRepositoryManager;
import org.eclipse.equinox.p2.repository.artifact.spi.ArtifactDescriptor;
import org.eclipse.equinox.p2.repository.metadata.IMetadataRepository;
import org.eclipse.equinox.p2.repository.metadata.IMetadataRepositoryManager;
import org.eclipse.equinox.spi.p2.publisher.PublisherHelper;
import org.eclipse.osgi.util.ManifestElement;
import org.json.JSONObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.ctc.wstx.stax.WstxOutputFactory;

@SuppressWarnings("restriction")
public class SBOMApplication implements IApplication {

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

	private static final URI SBOM_RENDERER_URI = URI.create("https://download.eclipse.org/cbi/sbom");

	private static final Pattern MAVEN_POM_PATTERN = Pattern.compile("META-INF/maven/[^/]+/[^/]+/pom.xml");

	private static final Pattern META_INF_FILE_PATTERN = Pattern.compile("META-INF/[^/]+");

	private static final Pattern LICENSE_FILE_PATTERN = Pattern.compile("(.*/)?LICENSE[^/]*(\\.txt)?$");

	private static final Pattern BUNDLE_PROPERTIES_PATTERN = Pattern.compile("(.*/)?(bundle|plugin).properties$");

	private static final XPathFactory XPATH_FACTORY = XPathFactory.newInstance();

	private static final List<String> ALGORITHMS = List.of("MD5", "SHA-1", "SHA-256", "SHA-512", "SHA-384", "SHA3-256",
			"SHA3-384", "SHA3-512");

	private static final Collector<CharSequence, ?, String> INDENTED_PROPERTY_VALUE_COLLECTOR = Collectors
			.joining("\n      ", "\n      ", "\n    ");

	private static final String METADATA_ARTIFACT = "metadata";

	private static boolean queryCentral;

	private static boolean isMetadata(IArtifactDescriptor artifactDescriptor) {
		return METADATA_ARTIFACT.equals(artifactDescriptor.getArtifactKey().getClassifier());
	}

	@Override
	public Object start(IApplicationContext context) throws Exception {
		var args = getArguments(context);
		var sbomGeneratorResults = new ArrayList<SBOMGenerator.Result>();
		var installationsFolder = getArgument("-installations", args, null);
		var verbose = getArgument("-verbose", args);
		SBOMApplication.queryCentral = getArgument("-central-search", args);
		if (installationsFolder != null) {
			var installationPattern = Pattern
					.compile(getArgument("-installation-pattern", args, ".*\\.(zip|tar|tar.gz)$"));
			var xmlOutputsFolder = getArgument("-xml-outputs", args, null);
			var jsonOutputsFolder = getArgument("-json-outputs", args, null);
			try (var contents = Files.newDirectoryStream(Path.of(installationsFolder).toAbsolutePath(),
					path -> installationPattern.matcher(path.getFileName().toString()).matches())) {
				for (Path path : contents) {
					var effectiveArgs = new ArrayList<>(args);
					if (verbose) {
						effectiveArgs.add(0, "-verbose");
					}
					effectiveArgs.add("-installation");
					effectiveArgs.add(path.toString());
					if (xmlOutputsFolder != null) {
						effectiveArgs.add("-xml-output");
						effectiveArgs.add(xmlOutputsFolder + "/"
								+ path.getFileName().toString().replaceAll("\\.(zip|tar|tar.gz)$", "-sbom.xml"));
					}
					if (jsonOutputsFolder != null) {
						effectiveArgs.add("-json-output");
						effectiveArgs.add(jsonOutputsFolder + "/"
								+ path.getFileName().toString().replaceAll("\\.(zip|tar|tar.gz)$", "-sbom.json"));
					}
					sbomGeneratorResults.add(new SBOMGenerator(effectiveArgs).run());
				}
			}
		} else {
			var effectiveArgs = new ArrayList<>(args);
			if (verbose) {
				effectiveArgs.add(0, "-verbose");
			}
			sbomGeneratorResults.add(new SBOMGenerator(effectiveArgs).run());
		}

		var index = getArgument("-index", args, null);
		if (index != null) {
			var indexPath = Path.of(index).toAbsolutePath();
			if (verbose) {
				System.out.println("Generating Index: " + index);
			}
			var render = getArgument("-renderer", args, SBOM_RENDERER_URI.toString());
			generateIndex(indexPath, URI.create(render), sbomGeneratorResults);

			var previewRedirections = URIUtil.parseRedirections(getArguments("-preview", args, List.of()));
			var redirectedIndex = URIUtil.getRedirectedURI(toURI(indexPath), previewRedirections);
			if (!"file".equals(redirectedIndex.getScheme())) {
				URIUtil.openURL(redirectedIndex);
			}
		}

		return EXIT_OK;
	}

	private void generateIndex(Path indexPath, URI renderer, List<SBOMGenerator.Result> sbomGeneratorResults)
			throws IOException {
		var html = """
				<!DOCTYPE html>
				<html lang=en>
				<head>
					<title>SBOM Index</title>
					<link rel="icon" type="image/ico" href="https://download.eclipse.org/cbi/sbom/favicon.ico">
						<style>
							img {
								max-height: 3ex;
							}

						</style>
				</head>
				<body>
					<table>
						${items}
					</table>

					<script>
						// This allows the arguments to the file query parameter to be relative such that the folder with the index.html and the SBOMs is portable.
						for (const a of document.querySelectorAll('a')) {
							const href = a.href;
							const match = /(?<renderer>.*\\?file=)(?<file>.*)/.exec(href);
							if (match) {
								const renderer = match.groups.renderer;
								const file = match.groups.file;
								const resolvedURL = new URL(file, location);
								a.href = `${renderer}${resolvedURL}`;
							}
						}
					</script>
				</body>
				</html>
				""";

		html = html.replace("${title}", "SBOM Index");
		var items = new ArrayList<String>();
		for (var sbomGenerator : sbomGeneratorResults) {
			var content = new ArrayList<String>();
			var inputs = sbomGenerator.inputs();
			var inputLinks = inputs.stream().map(SBOMApplication::toLink)
					.collect(Collectors.joining("<br/>", "<td>", "</td>"));
			content.add(inputLinks);

			var outputs = sbomGenerator.outputs();
			for (var output : outputs) {
				var relativize = indexPath.getParent().relativize(output);
				var label = relativize.toString().endsWith(".json") ? "json" : "xml";
				var hrefs = """
						<td><a href="${renderer}/?file=${file}"><img src="https://img.shields.io/static/v1?logo=eclipseide&label=Rendered&message=${label}&style=for-the-badge&logoColor=gray&labelColor=rgb(255,164,44)&color=gray"/></a></td>
						                  <td><a href="${file}"><img src="https://img.shields.io/static/v1?logo=eclipseide&label=Raw&message=${label}&style=for-the-badge&logoColor=gray&labelColor=rgb(255,164,44)&color=gray"/></a></td>
						""";
				hrefs = hrefs.replace("${renderer}", renderer.toString()).replace("${file}", relativize.toString())
						.replace("${label}", label);
				content.add(hrefs);
			}

			var item = """
					<tr>
						${content}
					</tr>
					""";
			items.add(item.replace("${content}", String.join("\n", content).replace("\n", "\n	")));
		}

		var formattedItems = String.join("\n", items).replace("\n", "\n		");
		html = html.replace("${items}", formattedItems);
		Files.writeString(indexPath, html);
	}

	private static String toLink(URI uri) {
		var value = uri.toString();
		var ARCHIVE_PATTERN = Pattern.compile("archive:(.*)!/.*");
		var archiveMatcher = ARCHIVE_PATTERN.matcher(value);
		var baseURI = archiveMatcher.matches() ? archiveMatcher.group(1) : value;
		// var NAME_PATTERN = Pattern.compile(".*/([^/]+)");
		// var nameMatcher = NAME_PATTERN.matcher(baseURI);
		// var name = nameMatcher.matches() ? nameMatcher.group(1) : baseURI;
		return "<a href='" + baseURI + "'>" + baseURI + "</a>";
	}

	@Override
	public void stop() {
	}

	private static class SBOMGenerator extends AbstractApplication {

		private static final char ZERO_WIDTH_SPACE = '\u200B';

		private static final String A_JRE_JAVASE_ID = "a.jre.javase";

		private static final Pattern ACCEPTED_LICENSE_URL_PATTERN = Pattern
				.compile(".*(documents/epl-v10|epl-v20|legal|license|/MPL).*[^/]", Pattern.CASE_INSENSITIVE);

		private static final Pattern POTENTIAL_LICENSE_REFERENCE_PATTERN = Pattern
				.compile("href=['\"]https?://(.*?)[/\r\n ]*['\"]");

		private static final Pattern EPL_10_NAME_PATTERN = Pattern.compile("epl-?(1.0|v10).*.html?");

		private static final Pattern EPL_20_NAME_PATTERN = Pattern.compile("epl-?(2.0|v20).*.html?");

		private static final Pattern EDL_10_NAME_PATTERN = Pattern.compile("edl-?(1.0|v10).*.html?");

		private static final Pattern APACHE_PUBLIC_LICENSE_20_PATTERN = Pattern.compile(
				"Apache License\\s+\\*?\\s*Version 2.0, January 2004\\s+\\*?\\s*http://www.apache.org/licenses/");

		private static final Pattern GPL_21_PATTERN = Pattern
				.compile("\\s*GNU LESSER GENERAL PUBLIC LICENSE\\s+Version 2\\.1, February 1999");

		private static final Pattern SPDX_ID_PATTERN = Pattern
				.compile("SPDX-License-Identifier:\\s((with\r?\n|[^\r\n\"\\\\|#])+)");

		private static final Pattern FEATURE_JAR_PATTERN = Pattern.compile("(.*\\.feature)\\.jar");

		private static final Pattern SOURCE_IU_PATTERN = Pattern.compile("(.*)\\.source(\\.feature\\.group|)");

		private static final Pattern GITHUB_SCM_PATTERN = Pattern
				.compile("(scm:)?(git:)?https?://github\\.com/(?<repo>[^/]+/[^/]+?)(\\.git)?");

		private static final Pattern TOUCHPOINT_FORMATTTING_PATTERN = Pattern.compile("\n( *)");

		private final Set<String> rejectedURLs = new TreeSet<>();

		private final Set<String> allLicenses = new TreeSet<>();

		private final Set<IMetadataRepository> metadataRepositories = new LinkedHashSet<>();

		private final Map<IArtifactKey, IInstallableUnit> artifactIUs = new TreeMap<>(ARTIFACT_COMPARATOR);

		private final Map<IArtifactKey, IArtifactDescriptor> artifactDescriptors = new HashMap<>();

		private final Map<IInstallableUnit, IInstallableUnit> featureJarsToFeatures = new HashMap<>();

		private final Map<IInstallableUnit, IInstallableUnit> featuresToFeatureJars = new HashMap<>();

		private final Map<IInstallableUnit, Component> iuComponents = new LinkedHashMap<>();

		private final List<URI> combinedRepositoryURIs = new ArrayList<>();

		private final List<URI> metadataRepositoryURIs = new ArrayList<>();

		private final List<URI> artifactRepositoryURIs = new ArrayList<>();

		private final List<IInstallableUnit> inclusiveContextIUs = new ArrayList<>();

		private final List<IInstallableUnit> exclusiveContextIUs = new ArrayList<>();

		private final List<Pattern> expectedMissingArtifactIUPatterns = new ArrayList<>();

		private final Map<URI, URI> uriRedirections;

		private final List<Path> outputs = new ArrayList<>();

		private final ContentHandler contentHandler;

		private final SPDXIndex spdxIndex;

		private final boolean verbose;

		private final boolean xml;

		private final String xmlOutput;

		private final boolean json;

		private final String jsonOutput;

		private final URI installationLocation;

		private IMetadataRepositoryManager metadataRepositoryManager;

		private IArtifactRepositoryManager artifactRepositoryManager;

		private SBOMGenerator(List<String> args) throws Exception {
			contentHandler = new ContentHandler(getArgument("-cache", args, null));
			spdxIndex = new SPDXIndex(contentHandler);

			verbose = getArgument("-verbose", args);

			uriRedirections = URIUtil.parseRedirections(getArguments("-redirections", args, List.of()));

			var installation = getArgument("-installation", args, null);
			if (installation != null) {
				installationLocation = handleInstallation(installation);
			} else {
				installationLocation = null;
			}

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
			metadataRepositoryURIs
					.addAll(getArguments("-metadata", args, List.of()).stream().map(URI::create).toList());
			artifactRepositoryURIs
					.addAll(getArguments("-artifact", args, List.of()).stream().map(URI::create).toList());

			xmlOutput = getArgument("-xml-output", args, null);
			jsonOutput = getArgument("-json-output", args, null);
			json = getArgument("-json", args);
			xml = getArgument("-xml", args) || !json && xmlOutput == null && jsonOutput == null;
		}

		private List<Path> getOutputs() {
			return outputs;
		}

		private List<URI> getInputs() {
			var result = new ArrayList<URI>();
			if (installationLocation != null) {
				result.add(getRedirectedURI(installationLocation));
			} else {
				result.addAll(combinedRepositoryURIs);
				result.addAll(metadataRepositoryURIs);
				result.addAll(artifactRepositoryURIs);
			}
			return result;
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
					? Path.of(
							p2DataArea.replaceAll("^@config.dir", configIni.getParent().toString().replace('\\', '/')))
					: Path.of(URI.create(p2DataArea));
			var profileFolder = resolvedDataArea
					.resolve("org.eclipse.equinox.p2.engine/profileRegistry/" + profileName + ".profile").normalize();
			metadataRepositoryURIs.add(toURI(profileFolder));
			return toURI(root);
		}

		private Path getInstallationPath(String installation) throws IOException {
			if (installation.startsWith("https://")) {
				var installationOriginatingURI = URI.create(installation);
				var extractedInstallation = extractInstallation(
						contentHandler.getContentCache(installationOriginatingURI));
				var installationParentURI = toURI(extractedInstallation.getParent().resolve("."));
				uriRedirections.put(installationParentURI, URI.create("archive:" + installationOriginatingURI + "!/"));
				return extractedInstallation;
			}
			var installationPath = Path.of(installation).toAbsolutePath();
			if (Files.isRegularFile(installationPath)) {
				var installationOriginatingURI = getRedirectedURI(toURI(installationPath));
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
			for (URI uri : metadataRepositoryManager.getKnownRepositories(IRepositoryManager.REPOSITORIES_ALL)) {
				metadataRepositoryManager.removeRepository(uri);
			}
			artifactRepositoryManager = super.getArtifactRepositoryManager();
			for (URI uri : artifactRepositoryManager.getKnownRepositories(IRepositoryManager.REPOSITORIES_ALL)) {
				artifactRepositoryManager.removeRepository(uri);
			}
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

		private void removeRepository(URI uri) {
			sourceRepositories.removeIf(it -> uri.equals(it.getRepoLocation()));
		}

		public Result run() throws ProvisionException {
			run(new NullProgressMonitor());
			return new Result(this);
		}

		@Override
		public IStatus run(IProgressMonitor monitor) throws ProvisionException {
			if (combinedRepositoryURIs.isEmpty() && metadataRepositoryURIs.isEmpty()) {
				System.err.println("An '-input' or '-metadata' argument is required");
				return Status.CANCEL_STATUS;
			}

			for (URI uri : combinedRepositoryURIs) {
				loadRepositories(uri, Set.of(IRepository.TYPE_METADATA, IRepository.TYPE_ARTIFACT), monitor);
			}

			for (URI uri : metadataRepositoryURIs) {
				loadRepositories(uri, Set.of(IRepository.TYPE_METADATA), monitor);
			}

			for (URI uri : artifactRepositoryURIs) {
				loadRepositories(uri, Set.of(IRepository.TYPE_ARTIFACT), monitor);
			}

			var artifactRepositoryManager = getArtifactRepositoryManager();
			var rootLocation = agent.getService(IAgentLocation.class).getRootLocation();
			for (URI uri : artifactRepositoryManager.getKnownRepositories(IRepositoryManager.REPOSITORIES_ALL)) {
				if (rootLocation.relativize(uri) != uri) {
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

			metadataRepositories.addAll(
					gatherSimpleRepositories(new HashSet<>(), new TreeMap<>(), getCompositeMetadataRepository()));

			addJRE(monitor);

			buildArtifactMappings();

			var bom = new Bom();

			var randomUUID = UUID.randomUUID();
			bom.setSerialNumber("urn:uuid:" + randomUUID);

			var executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 4);
			var futures = new LinkedHashSet<Future<?>>();

			// Build the basic component information available without I/O.
			var iusToDependencies = new LinkedHashMap<IInstallableUnit, Dependency>();
			for (var entry : artifactIUs.entrySet()) {
				var iu = entry.getValue();
				var component = createComponent(iu);
				iuComponents.put(iu, component);
				bom.addComponent(component);

				var artifactDescriptor = artifactDescriptors.get(entry.getKey());
				var bomRef = setBomRef(component, artifactDescriptor);

				var dependency = new Dependency(bomRef);
				bom.addDependency(dependency);
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
			}

			// Gather details from the actual artifacts in parallel.
			for (var entry : artifactIUs.entrySet()) {
				var iu = entry.getValue();
				var component = iuComponents.get(iu);
				var artifactDescriptor = artifactDescriptors.get(entry.getKey());
				futures.add(executor.submit(() -> {
					if (verbose) {
						System.out.println("Processing " + component.getBomRef());
					}

					var bytes = getArtifactContent(component, artifactDescriptor);
					setPurl(component, iu, artifactDescriptor, bytes);
					gatherLicences(component, iu, artifactDescriptor, bytes);
					resolveDependencies(iusToDependencies.get(iu), iu);
				}));
			}

			executor.shutdown();
			try {
				executor.awaitTermination(10, TimeUnit.MINUTES);
				var multiStatus = new MultiStatus(getClass(), 0, "Problems");
				for (var future : futures) {
					try {
						future.get();
					} catch (ExecutionException e) {
						var message = e.getMessage();
						if (verbose) {
							System.err.println("Execution exception: " + message);
						}
						multiStatus.add(new Status(IStatus.ERROR, getClass(), message, e));
					}
				}

				if (!multiStatus.isOK()) {
					throw new ProvisionException(multiStatus);
				}

			} catch (InterruptedException ex) {
				throw new ProvisionException("Took more than 10 minutes", ex);
			}

			// Transfer gathered details from binary IU to corresponding source IU.
			for (var entry : iuComponents.entrySet()) {
				var iu = entry.getKey();
				var component = entry.getValue();
				transferDetailsFromBinaryToSource(component, iu);
			}

			if (verbose) {
				System.out.println("licenes");
				allLicenses.stream().forEach(System.out::println);

				System.out.println();
				System.out.println("rejected-url");
				rejectedURLs.stream().forEach(System.out::println);
			}

			generateXML(bom);
			generateJson(bom);

			return Status.OK_STATUS;
		}

		private void buildArtifactMappings() {
			var metadataRepositoryManager = getMetadataRepositoryManager();
			var artifactRepository = getCompositeArtifactRepository();
			var metadataArtifacts = new HashSet<IInstallableUnit>();
			for (var iu : metadataRepositoryManager.query(QueryUtil.ALL_UNITS, null).toSet()) {
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
								var set = metadataRepositoryManager.query(iuQuery, null).toSet();
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
				if (iu.getId().endsWith(".feature.group")) {
					System.err.println("###");
				}
				associate(iu, createMetadataArtifactDecriptor(iu));
			}
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

			if (types.contains(IRepository.TYPE_METADATA)) {
				var metadataRepositoryManager = getMetadataRepositoryManager();
				var repository = metadataRepositoryManager.loadRepository(uri, monitor);
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
							}
							artifactRepositoryURIs.add(locationURI);
						}
					}
				}
			}

			if (types.contains(IRepository.TYPE_ARTIFACT)) {
				var artifactRepositoryManager = getArtifactRepositoryManager();
				artifactRepositoryManager.loadRepository(uri, monitor);
			}
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
			Map<String, String> properties = Stream.of(environments.split(",")).map(property -> property.split("="))
					.collect(Collectors.toMap(pair -> pair[0], pair -> pair[1]));
			return InstallableUnit.contextIU(properties);
		}

		private void addJRE(IProgressMonitor monitor) throws ProvisionException {
			if (metadataRepositoryManager.query(QueryUtil.createIUQuery(A_JRE_JAVASE_ID), null).isEmpty()) {
				var jreIU = JREAction.createJREIU();
				try {
					var jres = Files.createTempDirectory("jres");
					jres.toFile().deleteOnExit();
					var jresRepository = metadataRepositoryManager.createRepository(jres.toUri(), "JREs",
							IMetadataRepositoryManager.TYPE_SIMPLE_REPOSITORY, Map.of());
					jresRepository.addInstallableUnits(List.of(jreIU));
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

		private Component createAncestorComponent(MavenDescriptor mavenDescriptor) {
			var component = new Component();
			component.setType(Component.Type.LIBRARY);
			component.setName(mavenDescriptor.artifactId());
			component.setGroup(mavenDescriptor.groupId());
			component.setPurl(mavenDescriptor.mavenPURL());
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
						&& !key.endsWith(".providerName") //
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
						&& !IInstallableUnit.PROP_DESCRIPTION_URL.equals(key)
						&& !IInstallableUnit.PROP_CONTACT.equals(key) //
						&& !IInstallableUnit.PROP_PROVIDER.equals(key)//
						&& !IInstallableUnit.PROP_DOC_URL.equals(key) //
						&& !value.startsWith("%")) {
					component.addProperty(createProperty(key, value));
				}
			}

			var touchpointDetails = getTouchpointDetails(iu);
			if (touchpointDetails != null) {
				component.addProperty(createProperty("touchpoint", touchpointDetails));
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
			var mavenDescriptor = MavenDescriptor.create(iu, artifactDescriptor, bytes, contentHandler);
			if (mavenDescriptor != null && !mavenDescriptor.isSnapshot()) {
				try {
					// Document xmlContent =
					// contentHandler.getXMLContent(mavenDescriptor.toPOMURI());
					var mavenArtifactBytes = contentHandler.getBinaryContent(mavenDescriptor.toArtifactURI());

					// Call this only if the Maven artifact exists.
					getClearlyDefinedProperty(component, mavenDescriptor);

					// Only if the artifact is byte-for-byte equal do we generate a PURL reference
					// to the Maven artifact.
					if (Arrays.equals(bytes, mavenArtifactBytes)) {
						var purl = mavenDescriptor.mavenPURL();
						component.setPurl(purl);
						return;
					}

					// Otherwise record this as a pedigree ancestor component.
					var pedigree = new Pedigree();
					var ancenstors = new Ancestors();
					ancenstors.addComponent(createAncestorComponent(mavenDescriptor));
					pedigree.setAncestors(ancenstors);
					component.setPedigree(pedigree);
				} catch (ContentHandler.ContentHandlerException e) {
					// The only valid reason to fail is a 404,
					// i.e., resource does not exist on Maven Central.
					if (e.statusCode() != 404) {
						throw new RuntimeException(e);
					}
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}

			var location = getRedirectedURI(
					isMetadata(artifactDescriptor) ? URI.create(artifactDescriptor.getProperty("location"))
							: artifactDescriptor.getRepository().getLocation());
			var artifactKey = artifactDescriptor.getArtifactKey();
			var encodedLocation = urlEncodeQueryParameter(location.toString());
			var purl = "pkg:p2/" + artifactKey.getId() + "@" + artifactKey.getVersion() + "?classifier="
					+ artifactKey.getClassifier() + "&location=" + encodedLocation;
			component.setPurl(purl);
		}

		private URI getRedirectedURI(URI location) {
			return URIUtil.getRedirectedURI(location, uriRedirections);
		}

		private void getClearlyDefinedProperty(Component component, MavenDescriptor mavenDescriptor) {
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
								component.addProperty(BOMUtil.createProperty("clearly-defined", value));
							}
						}
					} catch (RuntimeException ex) {
						System.err.println("###" + clearlyDefinedURI);
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
				var out = new ByteArrayOutputStream();
				getCompositeArtifactRepository().getRawArtifact(artifactDescriptor, out, new NullProgressMonitor());
				bytes = out.toByteArray();

				for (String algorithm : ALGORITHMS) {
					component.addHash(new Hash(algorithm, computeHash(algorithm, bytes)));
				}
			}
			return bytes;
		}

		private void gatherLicences(Component component, IInstallableUnit iu, IArtifactDescriptor artifactDescriptor,
				byte[] bytes) {
			var licenseToName = new TreeMap<String, String>();
			if (bytes.length > 2 && bytes[0] == 0x50 && bytes[1] == 0x4B) {
				gatherLicencesFromJar(component, bytes, licenseToName);
			}

			var mavenDescriptor = MavenDescriptor.create(iu, artifactDescriptor, bytes, contentHandler);
			if (mavenDescriptor != null && !mavenDescriptor.isSnapshot()) {
				try {
					var content = contentHandler.getContent(mavenDescriptor.toPOMURI());
					gatherInformationFromPOM(component, content.getBytes(StandardCharsets.UTF_8), licenseToName);
				} catch (ContentHandler.ContentHandlerException e) {
					if (e.statusCode() != 404) {
						throw new RuntimeException(e);
					}
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}

			var licenses = iu.getLicenses(null);
			for (var license : licenses) {
				var location = license.getLocation();
				if (location != null) {
					var value = location.toString();
					if (!value.startsWith("%")) {
						licenseToName.putIfAbsent(value, null);
					}
				}
			}

			if (!licenseToName.isEmpty()) {
				var licenseChoice = new LicenseChoice();
				for (var licenseEntry : licenseToName.entrySet()) {
					var licenseName = licenseEntry.getValue();
					var url = licenseEntry.getKey();
					var license = new License();
					if (licenseName != null) {
						license.setName(licenseName);
					}
					license.setUrl(url);
					licenseChoice.addLicense(license);
				}
				component.setLicenses(licenseChoice);
			}
		}

		private void gatherLicencesFromJar(Component component, byte[] bytes, Map<String, String> licenseToName) {
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
							licenseToName.put("https://www.eclipse.org/legal/epl-v20.html", "EPL-2.0");
						} else if ("Eclipse Public License v1.0".equals(bundleLicense)) {
							licenseToName.put("https://www.eclipse.org/legal/epl-v10.html", "EPL-1.0");
						} else if ("The Apache License, Version 2.0".equals(bundleLicense)) {
							licenseToName.put("https://www.apache.org/licenses/LICENSE-2.0", "Apache-2.0");
						} else if (bundleLicense != null) {
							if ("Apache License, Version 2.0; see: http://www.apache.org/licenses/LICENSE-2.0.txt"
									.equals(bundleLicense)) {
								bundleLicense = "Apache-2.0;location=http://www.apache.org/licenses/LICENSE-2.0.txt";
							}
							var bundleLicenseElements = ManifestElement.parseHeader("Bundle-License", bundleLicense);
							for (var bundleLicenseElement : bundleLicenseElements) {
								var value = bundleLicenseElement.getValue();
								var linkAttribute = bundleLicenseElement.getAttribute("link");
								if (linkAttribute != null) {
									var links = linkAttribute.split(" *, *");
									for (var link : links) {
										licenseToName.put(link, value);
									}
								} else {
									if (value.startsWith("://")) {
										value = "https" + value;
									} else if ("jquery.com/license/".equals(value)
											|| "jquery.org/license".equals(value)) {
										value = "https://" + value;
									}
									if (!value.startsWith("http")) {
										var license = spdxIndex.getLicense(value);
										if (license != null) {
											licenseToName.put(license, value);
										} else {
											System.err.println("###");
										}
									} else {
										licenseToName.put(value, null);
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
												+ urlEncodeQueryParameter(
														eclipseSourceReferenceElement.getAttribute(key))))
										.collect(Collectors.joining("&", "?", ""));
								addExternalReference(component, ExternalReference.Type.VCS, value + query);
								addGitHubIssues(component, value);
							}
						}
					} else if (MAVEN_POM_PATTERN.matcher(name).matches()) {
						var allBytes = zip.readAllBytes();
						gatherInformationFromPOM(component, allBytes, licenseToName);
					} else if ("about.html".equals(name)) {
						var allBytes = zip.readAllBytes();
						gatherLicencesFromAbout(component, allBytes, licenseToName);
					} else if (EDL_10_NAME_PATTERN.matcher(name).matches()) {
						licenseToName.put("https://www.eclipse.org/org/documents/edl-v10.html", "EDL-1.0");
					} else if (EPL_20_NAME_PATTERN.matcher(name).matches()) {
						licenseToName.put("https://www.eclipse.org/legal/epl-v20.html", "EPL-2.0");
					} else if (EPL_10_NAME_PATTERN.matcher(name).matches()) {
						licenseToName.put("https://www.eclipse.org/legal/epl-v10.html", "EPL-1.0");
					} else if (META_INF_FILE_PATTERN.matcher(name).matches()) {
						if (!name.endsWith(".RSA") && !name.endsWith(".SF") && !name.endsWith(".inf")
								&& !name.endsWith(".DSA") && !name.endsWith("DEPENDENCIES")) {
							var allBytes = zip.readAllBytes();
							gatherLicencesFromFile(allBytes, licenseToName);
						}
					} else if (BUNDLE_PROPERTIES_PATTERN.matcher(name).matches()) {
						var allBytes = zip.readAllBytes();
						gatherLicencesFromFile(allBytes, licenseToName);
					} else if (LICENSE_FILE_PATTERN.matcher(name).matches()) {
						var allBytes = zip.readAllBytes();
						gatherLicencesFromFile(allBytes, licenseToName);
					}
					zip.closeEntry();
				}
			} catch (Exception ex) {
				throw new RuntimeException(ex);
			}
		}

		private void addGitHubIssues(Component component, String value) {
			var matcher = GITHUB_SCM_PATTERN.matcher(value);
			if (matcher.matches()) {
				var uri = URI.create("https://github.com/" + matcher.group("repo") + "/issues");
				if (contentHandler.exists(uri)) {
					addExternalReference(component, ExternalReference.Type.ISSUE_TRACKER, uri.toString());
				}
			}
		}

		private void gatherLicencesFromFile(byte[] bytes, Map<String, String> licenseToName) {
			var content = new String(bytes, StandardCharsets.UTF_8);
			if (APACHE_PUBLIC_LICENSE_20_PATTERN.matcher(content).find()) {
				licenseToName.put("https://www.apache.org/licenses/LICENSE-2.0", "Apache-2.0");
			} else if (GPL_21_PATTERN.matcher(content).find()) {
				licenseToName.put("https://spdx.org/licenses/LGPL-2.1-only.html", "LGPL-2.1-only");
			} else if (content.contains("The Apache Software License, Version 1.1")) {
				licenseToName.put("http://www.apache.org/licenses/LICENSE-1.1", "Apache-1.1");
			} else if (content.startsWith("BSD License")) {
				licenseToName.put("https://spdx.org/licenses/0BSD.html", "0BSD");
			} else if (content.startsWith("# Eclipse Public License - v 2.0")
					|| content.startsWith("Eclipse Public License - v 2.0")) {
				licenseToName.put("https://www.eclipse.org/legal/epl-v20.html", "EPL-2.0");
			} else if (content.contains("IBM Public License Version 1.0")) {
				licenseToName.put("https://spdx.org/licenses/IPL-1.0.html", "IBM Public License v1.0");
			} else {
				// SPDX-License-Identifier: BSD-3-Clause
				var matcher = SPDX_ID_PATTERN.matcher(content);
				if (matcher.find()) {
					do {
						var spdxId = matcher.group(1).trim();
						var license = spdxIndex.getLicense(spdxId);
						if (license != null) {
							licenseToName.put(license, spdxId);
						} else {
							var parts = spdxId.replaceAll("[()]", "")
									.split("\\s+OR\\s+|\\s+AND\\s+|\\s+WITH\\s+|\\s+with\\s+");
							if (parts.length > 1) {
								for (var part : parts) {
									license = spdxIndex.getLicense(part);
									if (license != null) {
										licenseToName.put(license, spdxId);
									} else {
										System.err.println("####?>>'" + part + "'");
									}
								}
							} else {
								System.err.println("####?>'" + spdxId + "'");
							}
						}
					} while (matcher.find());
				} else {
					// System.err.println("###");
				}
			}
		}

		private void gatherLicencesFromAbout(Component component, byte[] bytes, Map<String, String> licenseToName) {
			var content = new String(bytes, StandardCharsets.UTF_8);
			var urls = new ArrayList<String>();
			for (var matcher = POTENTIAL_LICENSE_REFERENCE_PATTERN.matcher(content); matcher.find();) {
				var url = "https://" + matcher.group(1);
				if (ACCEPTED_LICENSE_URL_PATTERN.matcher(url).matches()) {
					allLicenses.add(url);
					urls.add(url);
				} else if (!url.endsWith(".xsd") && !url.endsWith(".dtd")) {
					rejectedURLs.add(url);
				}
			}

			for (var url : urls) {
				var old = licenseToName.put(url, null);
				if (old != null) {
					licenseToName.put(url, old);
				}
			}

			if (content.indexOf("Eclipse Distribution License - v 1.0") != -1
					|| content.indexOf("Eclipse Distribution License - Version 1.0") != -1) {
				licenseToName.put("https://www.eclipse.org/org/documents/edl-v10.html", "edl-v10");
			}

			if (content.indexOf("Eclipse Public License Version 2.0") != -1) {
				licenseToName.put("https://www.eclipse.org/legal/epl-v20.html", "EPL-2.0");
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

		private void gatherInformationFromPOM(Component component, Document document,
				Map<String, String> licenseToName) {
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
					var parts = url.split(" *, *");
					for (var part : parts) {
						licenseToName.put(part, name);
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
			for (Pattern expectedMissingArtifactIUPattern : expectedMissingArtifactIUPatterns) {
				if (expectedMissingArtifactIUPattern.matcher(value).matches()) {
					return true;
				}
			}
			return false;
		}

		private void resolveDependencies(Dependency dependency, IInstallableUnit iu) {
			var metadataRepositoryManager = getMetadataRepositoryManager();
			var component = iuComponents.get(iu);
			var componentBomRef = component.getBomRef();

			var featureGroupIU = featureJarsToFeatures.get(iu);
			for (var requirement : (featureGroupIU == null ? iu : featureGroupIU).getRequirements()) {
				if (isExcluded(requirement)) {
					continue;
				}

				var matches = requirement.getMatches();
				var requiredIUs = metadataRepositoryManager.query(QueryUtil.createMatchQuery(matches), null).toSet();
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
						component
								.addProperty(BOMUtil.createProperty("unsatisfied-requirement", requirement.toString()));
					}
				} else {
					for (var requiredIU : requiredIUs) {
						var featureJar = featuresToFeatureJars.get(requiredIU);
						var requiredComponent = iuComponents.get(featureJar == null ? requiredIU : featureJar);
						if (requiredComponent == null) {
							if (!requiredIU.getId().startsWith(A_JRE_JAVASE_ID)) {
								if (verbose) {
									System.out.println("requirement-not-mapped-to-artifact=" + requiredIU);
								}
							}
						} else {
							var bomRef = requiredComponent.getBomRef();
							if (!componentBomRef.equals(bomRef)) {
								dependency.addDependency(new Dependency(bomRef));
							}
						}
					}
				}
			}
		}

		private void transferDetailsFromBinaryToSource(Component component, IInstallableUnit iu) {
			var id = iu.getId();
			var matcher = SOURCE_IU_PATTERN.matcher(id);
			if (matcher.matches()) {
				var description = new InstallableUnitDescription();
				description.setId(matcher.group(1) + matcher.group(2));
				description.setVersion(iu.getVersion());
				var binaryIU = MetadataFactory.createInstallableUnit(description);
				var binaryFeatureJarIU = featuresToFeatureJars.get(binaryIU);
				var binaryComponent = iuComponents.get(binaryFeatureJarIU == null ? binaryIU : binaryFeatureJarIU);
				if (binaryComponent != null) {
					var licenseChoice = component.getLicenses();
					if (licenseChoice == null) {
						component.setLicenses(binaryComponent.getLicenses());
					}
					var externalReferences = component.getExternalReferences();
					if (externalReferences == null || externalReferences.isEmpty()) {
						component.setExternalReferences(binaryComponent.getExternalReferences());
					}
				} else {
					System.err.println("## missing binary" + id);
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
			return new String(out.toByteArray(), StandardCharsets.UTF_8).replaceAll("<\\?.*?\\?>", "").trim()
					.replace("\r", "");
		}

		private void generateJson(Bom bom) {
			if (json || jsonOutput != null) {
				var undoables = new ArrayList<Runnable>();
				try {
					// The json serialization of a property value collapses whitespace, including
					// line separators into a single space.
					for (var component : bom.getComponents()) {
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
					}
					var jsonGenerator = BomGeneratorFactory.createJson(Version.VERSION_16, bom);
					var jsonString = jsonGenerator.toJsonString();
					if (json) {
						System.out.println(jsonString);
					}
					if (jsonOutput != null) {
						var output = Path.of(jsonOutput).toAbsolutePath();
						outputs.add(output);
						Files.writeString(output, jsonString);

					}
				} catch (Exception ex) {
					throw new RuntimeException(ex);
				} finally {
					undoables.forEach(Runnable::run);
				}
			}
		}

		public static record Result(List<URI> inputs, List<Path> outputs) {
			public Result(SBOMGenerator sbomGenerator) {
				this(sbomGenerator.getInputs(), sbomGenerator.getOutputs());
			}
		}
	}

	public static final class XMLUtil {

		private static final DocumentBuilderFactory FACTORY;

		private XMLUtil() {
		}

		static {
			FACTORY = DocumentBuilderFactory.newInstance();
			FACTORY.setNamespaceAware(true);
			FACTORY.setValidating(false);
			try {
				FACTORY.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
				FACTORY.setFeature("http://xml.org/sax/features/external-general-entities", false);
				FACTORY.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
			} catch (ParserConfigurationException e) {
				throw new RuntimeException(e.getMessage(), e);
			}
		}

		public static DocumentBuilder newDocumentBuilder() throws ParserConfigurationException {
			return FACTORY.newDocumentBuilder();
		}

		public static String getText(Element element, String name) {
			var nodeList = element.getElementsByTagName(name);
			if (nodeList.getLength() > 0) {
				return nodeList.item(0).getTextContent();
			}
			return null;
		}

		public static List<Element> evaluate(Node node, String expression) {
			var xPath = XPATH_FACTORY.newXPath();
			try {
				var document = node instanceof Document doc ? doc : node.getOwnerDocument();
				xPath.setNamespaceContext(new NamespaceContext() {
					@Override
					public String getNamespaceURI(String prefix) {
						if (prefix.equals(XMLConstants.DEFAULT_NS_PREFIX)) {
							return document.lookupNamespaceURI(null);
						}
						var result = document.lookupNamespaceURI(prefix);
						if (result == null) {
							result = document.lookupNamespaceURI(null);
						}
						if (result == null && "pom".equals(prefix)) {
							return "http://maven.apache.org/POM/4.0.0";
						}
						return result;
					}

					@Override
					public Iterator<String> getPrefixes(String val) {
						return null;
					}

					@Override
					public String getPrefix(String namespaceURI) {
						return document.lookupPrefix(namespaceURI);
					}
				});

				var nodeList = (NodeList) xPath.compile(expression).evaluate(node, XPathConstants.NODESET);
				var result = new ArrayList<Element>();
				for (int i = 0, length = nodeList.getLength(); i < length; ++i) {
					result.add((Element) nodeList.item(i));
				}
				return result;
			} catch (XPathExpressionException e) {
				throw new IllegalArgumentException(expression);
			}
		}
	}

	record MavenDescriptor(String groupId, String artifactId, String version, String classifier, String type) {
		public static MavenDescriptor create(IInstallableUnit iu, IArtifactDescriptor artifactDescriptor, byte[] bytes,
				ContentHandler contentHandler) {
			var mavenDescriptor = create(artifactDescriptor.getProperties());
			if (mavenDescriptor == null) {
				mavenDescriptor = create(iu.getProperties());
			}
			if (mavenDescriptor == null && !isMetadata(artifactDescriptor)) {
				try (var stream = new JarInputStream(new ByteArrayInputStream(bytes))) {
					ZipEntry entry;
					while ((entry = stream.getNextEntry()) != null) {
						var name = entry.getName();
						if (name.startsWith("META-INF/maven/") && name.endsWith("pom.properties")) {
							var properties = new Properties();
							properties.load(stream);
							var artifactId = properties.getProperty("artifactId");
							var groupId = properties.getProperty("groupId");
							var version = properties.getProperty("version");
							if (artifactId != null && groupId != null && version != null) {
								return new MavenDescriptor(groupId, artifactId, version, null, "jar");
							}
						}
					}
				} catch (IOException e) {
					// If anything goes wrong we can not do much more at this stage...
				}
				if (queryCentral) {
					// This is not the end we can try to query maven central
					try {
						var sha1Hash = computeHash("SHA-1", bytes);
						var queryResult = contentHandler.getContent(URI
								.create("https://central.sonatype.com/solrsearch/select?q=1:" + sha1Hash + "&wt=json"));
						var jsonObject = new JSONObject(queryResult);
						if (jsonObject.has("response")) {
							var response = jsonObject.getJSONObject("response");
							if (response.has("numFound") && response.getInt("numFound") == 1) {
								var coordinates = response.getJSONArray("docs").getJSONObject(0);
								return new MavenDescriptor(coordinates.getString("g"), coordinates.getString("a"),
										coordinates.getString("v"), null, coordinates.getString("p"));
							}
						}
					} catch (Exception e) {
						// If anything goes wrong here, we can not do much more ...
					}
				}
				// System.err.println("###" + artifactDescriptor);
			}
			return mavenDescriptor;
		}

		public static MavenDescriptor create(Map<String, String> properties) {
			var mavenGroupId = properties.get("maven-groupId");
			if (mavenGroupId == null) {
				mavenGroupId = properties.get("maven-wrapped-groupId");
			}

			var mavenArtifactId = properties.get("maven-artifactId");
			if (mavenArtifactId == null) {
				mavenArtifactId = properties.get("maven-wrapped-artifactId");
			}

			var mavenVersion = properties.get("maven-version");
			if (mavenVersion == null) {
				mavenVersion = properties.get("maven-wrapped-version");
			}

			var mavenClassifier = properties.get("maven-classifier");
			if (mavenClassifier == null) {
				mavenClassifier = properties.get("maven-wrapped-classifier");
			}

			var mavenType = properties.get("maven-type");
			if (mavenType == null) {
				mavenType = properties.get("maven-wrapped-type");
			}

			if (mavenGroupId != null && mavenArtifactId != null && mavenVersion != null) {
				return new MavenDescriptor(mavenGroupId, mavenArtifactId, mavenVersion,
						mavenClassifier == null || mavenClassifier.isBlank() ? null : mavenClassifier,
						mavenType == null || mavenType.isBlank() ? "jar" : mavenType);
			}

			return null;
		}

		public boolean isSnapshot() {
			return version.endsWith("-SNAPSHOT");
		}

		public URI toPOMURI() {
			return toURI(".pom");
		}

		public URI toArtifactURI() {
			return toURI((classifier == null ? "" : '-' + classifier) + "." + type);
		}

		public URI toClearlyDefinedURI() {
			return URI.create("https://api.clearlydefined.io/definitions/maven/mavencentral/" + groupId + "/"
					+ artifactId + "/" + version);
		}

		public String mavenPURL() {
			var qualifiers = new LinkedHashMap<String, String>();
			if (!"jar".equals(type)) {
				qualifiers.put("type", type);
			}
			if (classifier != null) {
				qualifiers.put("classifier", classifier);
			}
			var query = qualifiers.isEmpty() ? ""
					: qualifiers.entrySet().stream().map(Object::toString).collect(Collectors.joining("&", "?", ""));
			return "pkg:maven/" + groupId + '/' + artifactId + '@' + version + query;
		}

		private URI toURI(String suffix) {
			return URI.create("https://repo.maven.apache.org/maven2/" + groupId.replace('.', '/') + "/" + artifactId
					+ "/" + version + "/" + artifactId + "-" + version + suffix);
		}
	}

	public final static class SPDXIndex {

		private final Map<String, String> spdxLicenceIds = new TreeMap<>();

		private final Map<String, String> spdxLicenceNames = new TreeMap<>();

		public SPDXIndex(ContentHandler contentHandler) {
			try {
				buildSPDXIndex(contentHandler);
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		private void buildSPDXIndex(ContentHandler contentHandler) throws IOException {
			buildSPDXIndex(contentHandler.getContent(URI.create("https://spdx.org/licenses/licenses.json")),
					"licenses");
			buildSPDXIndex(contentHandler.getContent(URI.create("https://spdx.org/licenses/exceptions.json")),
					"exceptions");
		}

		@SuppressWarnings("unchecked")
		private void buildSPDXIndex(String licenses, String property) {
			var jsonArray = new JSONObject(licenses).getJSONArray(property);
			for (var license : (Iterable<JSONObject>) (Iterable<?>) jsonArray) {
				var reference = license.getString("reference");

				var id = license.getString("exceptions".equals(property) ? "licenseExceptionId" : "licenseId");
				spdxLicenceIds.put(id, reference);

				var name = license.getString("name");
				spdxLicenceNames.put(name, reference);
			}
		}

		public String getLicense(String nameOrId) {
			var license = spdxLicenceIds.get(nameOrId);
			if (license == null) {
				license = spdxLicenceNames.get(nameOrId);
			}
			return license;
		}
	}

	public static class ContentHandler {

		public static class ContentHandlerException extends IOException {
			private static final long serialVersionUID = 1L;

			private final int statusCode;

			public ContentHandlerException(HttpResponse<?> response) {
				super("status code " + response.statusCode() + " -> " + response.uri());
				this.statusCode = response.statusCode();
			}

			public ContentHandlerException(int statusCode, URI uri) {
				super("status code " + statusCode + " -> " + uri);
				this.statusCode = statusCode;
			}

			public int statusCode() {
				return statusCode;
			}
		}

		private final Map<URI, Boolean> exists = new ConcurrentHashMap<>();

		private final Path cache;

		private final HttpClient httpClient;

		public ContentHandler(String cache) {
			httpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();

			try {
				if (cache != null) {
					this.cache = Path.of(cache).toAbsolutePath();
				} else {
					this.cache = Files.createTempDirectory("org.eclipse.cbi.p2repo.sbom.cache");
				}
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		private boolean isCacheExpired(Path path) {
			try {
				var lastModifiedTime = Files.getLastModifiedTime(path);
				var now = System.currentTimeMillis();
				var age = now - lastModifiedTime.toMillis();
				var ageInHours = age / 1000 / 60 / 60;
				return ageInHours > 8;
			} catch (IOException e) {
				return true;
			}
		}

		protected <T> T basicGetContent(URI uri, BodyHandler<T> bodyHandler) throws IOException, InterruptedException {
			var requestBuilder = HttpRequest.newBuilder(uri).GET();
			var request = requestBuilder.build();
			var response = httpClient.send(request, bodyHandler);
			var statusCode = response.statusCode();
			if (statusCode != 200) {
				throw new ContentHandlerException(response);
			}
			return response.body();
		}

		protected <T> T basicHead(URI uri, BodyHandler<T> bodyHandler) throws IOException, InterruptedException {
			var requestBuilder = HttpRequest.newBuilder(uri).method("HEAD", BodyPublishers.noBody());
			var request = requestBuilder.build();
			var response = httpClient.send(request, bodyHandler);
			var statusCode = response.statusCode();
			if (statusCode != 200) {
				throw new ContentHandlerException(response);
			}
			return response.body();
		}

		protected Path getCachePath404(URI uri) {
			return getCachePath(uri, "404/");
		}

		protected Path getCachePath(URI uri) {
			return getCachePath(uri, "");
		}

		private Path getCachePath(URI uri, String prefix) {
			var decodedURI = URLDecoder.decode(uri.toString(), StandardCharsets.UTF_8);
			var uriSegments = decodedURI.split("[:/?#&;]+");
			var result = cache.resolve(prefix + String.join("/", uriSegments));
			return result;
		}

		interface Reader<T> {
			T read(Path path) throws IOException;
		}

		interface Writer<T> {
			void write(Path path, T t) throws IOException;
		}

		public boolean exists(URI uri) {
			return exists.computeIfAbsent(uri, u -> {
				var path = getCachePath(uri);
				if (Files.isRegularFile(path) && !isCacheExpired(path)) {
					return true;
				}

				var path404 = getCachePath404(uri);
				if (Files.isRegularFile(path404) && !isCacheExpired(path404)) {
					return false;
				}

				try {
					Files.createDirectories(path.getParent());
					basicHead(uri, BodyHandlers.ofString());
					Files.writeString(path, "");
					return true;
				} catch (ContentHandlerException e) {
					if (e.statusCode() == 404) {
						try {
							Files.createDirectories(path404.getParent());
							Files.writeString(path404, "");
						} catch (IOException e1) {
							throw new RuntimeException(e);
						}
						return false;
					}
					throw new RuntimeException(e);
				} catch (IOException | InterruptedException e) {
					throw new RuntimeException(e);
				}
			});
		}

		public String getContent(URI uri) throws IOException {
			return getContent(uri, Files::readString, Files::writeString, BodyHandlers.ofString());
		}

		public byte[] getBinaryContent(URI uri) throws IOException {
			return getContent(uri, Files::readAllBytes, Files::write, BodyHandlers.ofByteArray());
		}

		public Path getContentCache(URI uri) throws IOException {
			return getContent(uri, path -> path, (path, t) -> {
			}, BodyHandlers.ofFile(getCachePath(uri)));
		}

		public <T> T getContent(URI uri, Reader<T> reader, Writer<T> writer, BodyHandler<T> bodyHandler)
				throws IOException {
			if ("file".equals(uri.getScheme())) {
				return reader.read(Path.of(uri));
			}

			var path = getCachePath(uri);
			if (Files.isRegularFile(path) && !isCacheExpired(path)) {
				return reader.read(path);
			}

			var path404 = getCachePath404(uri);
			if (Files.isRegularFile(path404) && !isCacheExpired(path404)) {
				throw new ContentHandlerException(404, uri);
			}

			try {
				Files.createDirectories(path.getParent());
				var content = basicGetContent(uri, bodyHandler);
				writer.write(path, content);
				return content;
			} catch (ContentHandlerException e) {
				if (e.statusCode() == 404) {
					Files.createDirectories(path404.getParent());
					Files.writeString(path404, "");
				}
				throw e;
			} catch (InterruptedException e) {
				throw new IOException(e);
			}
		}

		public Document getXMLContent(URI uri) throws IOException {
			var content = getContent(uri);
			try {
				var builder = newDocumentBuilder();
				return builder.parse(new InputSource(new StringReader(content)));
			} catch (ParserConfigurationException | SAXException e) {
				throw new IOException(uri + " : " + e.getMessage(), e);
			}
		}
	}

	public static final class ArgumentUtil {
		private ArgumentUtil() {
		}

		public static List<String> getArguments(IApplicationContext context) {
			return new ArrayList<>(Arrays.asList((String[]) context.getArguments().get("application.args")));
		}

		public static boolean getArgument(String name, List<String> args) {
			return args.remove(name);
		}

		public static String getArgument(String name, List<String> args, String defaultValue) {
			var index = args.indexOf(name);
			if (index == -1) {
				return defaultValue;
			}
			args.remove(index);
			if (index >= args.size()) {
				throw new IllegalArgumentException("An argument value is expected after " + name);
			}
			return args.remove(index);
		}

		public static List<String> getArguments(String name, List<String> args, List<String> defaultValue) {
			var index = args.indexOf(name);
			if (index == -1) {
				return defaultValue;
			}
			args.remove(index);
			if (index >= args.size()) {
				throw new IllegalArgumentException("An argument value is expected after " + name);
			}

			var result = new ArrayList<String>();
			while (index < args.size() && !args.get(index).startsWith("-")) {
				result.add(args.remove(index));
			}
			return result;
		}
	}

	public static final class BOMUtil {
		public BOMUtil() {
		}

		public static BomXmlGenerator createBomXMLGenerator(Version version, Bom bom) {
			var thread = Thread.currentThread();
			var contextClassLoader = thread.getContextClassLoader();
			var propertyName = XMLOutputFactory.class.getName();
			var property = System.getProperty(propertyName);
			try {
				System.setProperty(propertyName, WstxOutputFactory.class.getName());
				thread.setContextClassLoader(SBOMApplication.class.getClassLoader());
				return BomGeneratorFactory.createXml(version, bom);
			} finally {
				if (property == null) {
					System.clearProperty(propertyName);
				} else {
					System.setProperty(propertyName, property);
				}
				thread.setContextClassLoader(contextClassLoader);
			}
		}

		public static Property createProperty(String name, String value) {
			var property = new Property();
			property.setName(name);
			property.setValue(value);
			return property;
		}

		public static void addAnnotation(Bom bom, String name, Stream<? extends CharSequence> values) {
			var annotations = bom.getAnnotations();
			if (annotations == null) {
				annotations = new ArrayList<>();
			}
			annotations.add(createAnnotation(name, values));
			bom.setAnnotations(annotations);
		}

		public static Annotation createAnnotation(String name, Stream<? extends CharSequence> values) {
			var annotation = new Annotation();
			annotation.setText(name + "=" + values.collect(INDENTED_PROPERTY_VALUE_COLLECTOR));
			return annotation;
		}

		public static Property createProperty(String name, Stream<? extends CharSequence> values) {
			var property = new Property();
			property.setName(name);
			property.setValue(values.collect(INDENTED_PROPERTY_VALUE_COLLECTOR));
			return property;
		}

		public static void addExternalReference(Component component, ExternalReference.Type type, String url) {
			var externalReference = createExternalReference(type, url);
			var externalReferences = component.getExternalReferences();
			if (externalReferences == null || !externalReferences.contains(externalReference)) {
				if (externalReferences != null) {
					for (ExternalReference otherExternalReference : externalReferences) {
						if (otherExternalReference.getType() == type) {
							var otherURL = otherExternalReference.getUrl();
							if (otherURL.startsWith(url)) {
								if (otherURL.charAt(url.length()) == '?') {
									return;
								}
							} else if (url.startsWith(otherURL)) {
								if (url.charAt(otherURL.length()) == '?') {
									otherExternalReference.setUrl(url);
									return;
								}
							}
						}
					}
				}
				component.addExternalReference(externalReference);
			}
		}

		public static ExternalReference createExternalReference(ExternalReference.Type type, String url) {
			var externalReference = new ExternalReference();
			externalReference.setType(type);
			externalReference.setUrl(url);
			return externalReference;
		}

		public static String computeHash(String algorithm, byte[] bytes) {
			try {
				var digest = MessageDigest.getInstance(algorithm);
				var result = digest.digest(bytes);
				return HexFormat.of().formatHex(result);
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException(e);
			}
		}

		public static String urlEncodeQueryParameter(String value) {
			// Decode characters such as / and: that are very common in URIs
			// and do not need to be encoded within a URI's query string.
			var result = URLEncoder.encode(value, StandardCharsets.UTF_8);
			return result.replace("%2F", "/").replace("%3A", ":");
		}
	}

	public static final class IOUtil {
		private static final Pattern SUPPORTED_ARCHIVE_PATTERN = Pattern
				.compile("(?<name>.*)\\.(?<extension>zip|tar|tar.gz)$");

		private IOUtil() {
		}

		public static Path extractInstallation(Path archive) throws IOException {
			var fileName = archive.getFileName().toString();
			var matcher = SUPPORTED_ARCHIVE_PATTERN.matcher(fileName);
			if (!matcher.matches()) {
				throw new IllegalArgumentException("Unsupported archive format");
			}
			var baseName = matcher.group("name");
			var extension = matcher.group("extension");
			var target = archive.resolveSibling(baseName);
			if (!Files.isDirectory(target)) {
				Files.createDirectory(target);
				switch (extension) {
				case "zip": {
					try (var in = Files.newInputStream(archive)) {
						extractZip(in, target);
					}
					break;
				}
				case "tar": {
					try (var in = Files.newInputStream(archive)) {
						extractTar(in, target);
					}
					break;
				}
				case "tar.gz": {
					try (InputStream in = new GzipCompressorInputStream(Files.newInputStream(archive))) {
						extractTar(in, target);
					}
					break;
				}
				}
			}

			try (var targetContents = Files.newDirectoryStream(target, Files::isDirectory)) {
				var paths = new ArrayList<Path>();
				for (Path path : targetContents) {
					paths.add(path);
				}
				if (paths.isEmpty()) {
					throw new IllegalArgumentException("The folder " + target + "is empty");
				}
				return paths.size() == 1 ? paths.get(0) : target;
			}
		}

		private static void extractZip(InputStream in, Path target) throws IOException {
			try (var tar = new ZipInputStream(in)) {
				for (var entry = tar.getNextEntry(); entry != null; entry = tar.getNextEntry()) {
					var path = target.resolve(entry.getName());
					if (entry.isDirectory()) {
						Files.createDirectory(path);
					} else {
						Files.copy(tar, path);
					}
				}
			}
		}

		private static void extractTar(InputStream in, Path target) throws IOException {
			try (var tar = new TarArchiveInputStream(in)) {
				for (var entry = tar.getNextEntry(); entry != null; entry = tar.getNextEntry()) {
					var path = target.resolve(entry.getName());
					if (entry.isDirectory()) {
						Files.createDirectory(path);
					} else {
						Files.copy(tar, path);
					}
				}
			}
		}
	}

	public static class URIUtil {
		public static void openURL(URI uri) throws IOException {
			Desktop.getDesktop().browse(uri);
		}

		public static URI toURI(String value) {
			return value.startsWith("https://") | value.startsWith("http://") ? URI.create(value)
					: toURI(Path.of(value).toAbsolutePath());
		}

		public static URI toURI(Path path) {
			return toURI(path.toUri());
		}

		public static URI toURI(URI uri) {
			return URI.create(uri.toString().replaceAll("file:///", "file:/").replaceAll("/$", "")).normalize();
		}

		public static URI getRedirectedURI(URI location, Map<URI, URI> uriRedirections) {
			for (var entry : uriRedirections.entrySet()) {
				var relativizedURI = entry.getKey().relativize(location);
				if (relativizedURI.getScheme() == null) {
					return getRedirectedURI(URI.create(entry.getValue().toString() + relativizedURI), uriRedirections);
				}
			}
			return location;
		}

		public static Map<URI, URI> parseRedirections(List<String> redirections) {
			var uriRedirections = new TreeMap<URI, URI>((o1, o2) -> {
				// Longest URI first for redirection.
				var result = Integer.compare(o2.toString().length(), o1.toString().length());
				return result == 0 ? o1.compareTo(o2) : result;
			});

			for (var uriRedirection : redirections) {
				var pair = uriRedirection.split("->");
				if (pair.length != 2) {
					throw new IllegalArgumentException("Expected a '->' in the redirection:" + uriRedirection);
				}
				uriRedirections.put(toURI(pair[0]), toURI(pair[1]));
			}

			return uriRedirections;
		}
	}
}
