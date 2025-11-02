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
import static org.eclipse.cbi.p2repo.sbom.URIUtil.getRedirectedURI;
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
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
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
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
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

	private static final Pattern ACCEPTED_LICENSE_URL_PATTERN = Pattern
			.compile(".*(documents/epl-v10|epl-v20|legal|license|/MPL).*[^/]", Pattern.CASE_INSENSITIVE);

	private static final Pattern POTENTIAL_LICENSE_REFERENCE_PATTERN = Pattern
			.compile("href=['\"]https?://(.*?)[/\r\n ]*['\"]");

	private static final Pattern EPL_10_NAME_PATTERN = Pattern.compile("epl-?(1.0|v10).*.html?");

	private static final Pattern EPL_20_NAME_PATTERN = Pattern.compile("epl-?(2.0|v20).*.html?");

	private static final Pattern EDL_10_NAME_PATTERN = Pattern.compile("edl-?(1.0|v10).*.html?");

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

	private static boolean isMetadata(IArtifactDescriptor artifactDescriptor) {
		return METADATA_ARTIFACT.equals(artifactDescriptor.getArtifactKey().getClassifier());
	}

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

	private final List<URI> p2ArtifactSourceRepositoryURIs = new ArrayList<>();

	private final List<ArtifactSourceRepository> artifactSourceRepositories = new ArrayList<>();

	private final boolean strictSourceRepositories;

	private final List<IInstallableUnit> inclusiveContextIUs = new ArrayList<>();

	private final List<IInstallableUnit> exclusiveContextIUs = new ArrayList<>();

	private final List<Pattern> expectedMissingArtifactIUPatterns = new ArrayList<>();

	private final List<Path> outputs = new ArrayList<>();

	private final List<String> arguments = new ArrayList<>();

	private final Map<URI, URI> uriRedirections;

	private final ByteCache byteCache;

	private final ContentHandler contentHandler;

	private final SPDXIndex spdxIndex;

	private final boolean verbose;

	private final boolean queryCentral;

	private final boolean xml;

	private final String xmlOutput;

	private final boolean json;

	private final String jsonOutput;

	private final URI installationLocation;

	private final boolean processBundleClassPath;

	private final boolean fetchAdvisory;

	private final boolean fetchClearlyDefined;

	private ClearlyDefinedApi clearlyDefinedApi;

	private final Bom bom;

	private IMetadataRepositoryManager metadataRepositoryManager;

	private IArtifactRepositoryManager artifactRepositoryManager;

	public SBOMGenerator(List<String> arguments) throws Exception {
		super(createAgent());

		this.arguments.addAll(arguments);

		var args = new ArrayList<>(arguments);

		verbose = getArgument("-verbose", args);

		contentHandler = new ContentHandler(getArgument("-cache", args, null));
		byteCache = new ByteCache(getArgument("-byte-cache", args, null));
		processBundleClassPath = getArgument("-process-bundle-classpath", args);
		spdxIndex = new SPDXIndex(contentHandler);

		queryCentral = getArgument("-central-search", args);

		fetchAdvisory = getArgument("-advisory", args);

		fetchClearlyDefined = getArgument("-clearly-defined", args);

		uriRedirections = parseRedirections(getArguments("-redirections", args, List.of()));

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
		metadataRepositoryURIs.addAll(getArguments("-metadata", args, List.of()).stream().map(URI::create).toList());
		artifactRepositoryURIs.addAll(getArguments("-artifact", args, List.of()).stream().map(URI::create).toList());
		p2ArtifactSourceRepositoryURIs
				.addAll(getArguments("-p2sources", args, getArguments("-p2-sources", args, List.of())).stream()
						.map(URI::create).toList());
		strictSourceRepositories = getArgument("-strict-p2-source-repositories", args);

		xmlOutput = getArgument("-xml-output", args, null);
		jsonOutput = getArgument("-json-output", args, null);
		json = getArgument("-json", args);
		xml = getArgument("-xml", args) || !json && xmlOutput == null && jsonOutput == null;

		bom = new Bom();
		var randomUUID = UUID.randomUUID();
		bom.setSerialNumber("urn:uuid:" + randomUUID);

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
			System.out.println("licenes");
			allLicenses.stream().forEach(System.out::println);

			System.out.println();
			System.out.println("rejected-url");
			rejectedURLs.stream().forEach(System.out::println);
		}

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
				combinedRepositoryURIs.size() * 2 + metadataRepositoryURIs.size() * 2 + artifactRepositoryURIs.size());
		for (var uri : combinedRepositoryURIs) {
			loadRepositories(uri, Set.of(IRepository.TYPE_METADATA, IRepository.TYPE_ARTIFACT),
					progress.split(1, SubMonitor.SUPPRESS_NONE));
		}

		for (var uri : metadataRepositoryURIs) {
			loadRepositories(uri, Set.of(IRepository.TYPE_METADATA), progress.split(1, SubMonitor.SUPPRESS_NONE));
		}

		for (var uri : artifactRepositoryURIs) {
			loadRepositories(uri, Set.of(IRepository.TYPE_ARTIFACT), progress.split(1, SubMonitor.SUPPRESS_NONE));
		}

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

		metadataRepositories
				.addAll(gatherSimpleRepositories(new HashSet<>(), new TreeMap<>(), getCompositeMetadataRepository()));

		addJRE(monitor);

		loadSourceRepositories();

		progress.done();
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

		progress.done();
		return iusToDependencies;
	}

	private void processArtifacts(Map<IInstallableUnit, Dependency> iusToDependencies, IProgressMonitor monitor)
			throws ProvisionException {
		var progress = SubMonitor.convert(monitor, "Processing Artifacts", artifactIUs.size());
		var completed = new AtomicInteger();
		var inProgress = new AtomicInteger();
		var remaining = new AtomicInteger(artifactIUs.size());
		Runnable subtaskUpdater = () -> {
			progress.subTask(" Completed: " + completed.get() + " Processing: " + inProgress.get() + " Remaining: "
					+ remaining.get());
		};

		// Gather details from the actual artifacts in parallel.
		var executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 4);
		
		// Initialize ClearlyDefinedApi with the shared executor if needed
		if (fetchClearlyDefined) {
			clearlyDefinedApi = new ClearlyDefinedApi(contentHandler, executor, verbose);
		}
		
		var futures = new LinkedHashSet<Future<?>>();
		for (var entry : artifactIUs.entrySet()) {
			var iu = entry.getValue();
			var component = iuComponents.get(iu);
			var artifactDescriptor = artifactDescriptors.get(entry.getKey());
			futures.add(executor.submit(() -> {
				if (verbose) {
					System.out.println("Processing " + component.getBomRef());
				}

				inProgress.incrementAndGet();
				subtaskUpdater.run();

				var bytes = getArtifactContent(component, artifactDescriptor);
				setPurl(component, iu, artifactDescriptor, bytes);
				gatherLicences(component, iu, artifactDescriptor, bytes);
				gatherInnerJars(component, bytes, artifactDescriptor);
				gatherAdvisory(component);
				resolveDependencies(iusToDependencies.get(iu), iu);

				progress.worked(1);
				completed.incrementAndGet();
				inProgress.decrementAndGet();
				remaining.decrementAndGet();
				subtaskUpdater.run();
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
			throw new ProvisionException("Took more than 10 minutes", ex);
		}

		progress.subTask("");
		
		// Wait for ClearlyDefined requests to complete
		if (clearlyDefinedApi != null) {
			try {
				clearlyDefinedApi.waitForCompletion();
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new ProvisionException("Interrupted while waiting for ClearlyDefined", e);
			}
		}
		
		progress.done();

		// Transfer gathered details from binary IU to corresponding source IU.
		for (var entry : iuComponents.entrySet()) {
			var iu = entry.getKey();
			var component = entry.getValue();
			transferDetailsFromBinaryToSource(component, iu);
		}
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
		var result = new ArrayList<URI>();
		if (installationLocation != null) {
			result.add(getRedirectedURIForRedirections(installationLocation));
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
			var installationOriginatingURI = getRedirectedURIForRedirections(toURI(installationPath));
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
				addHashes(subComponent, entry.getValue());
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

	private Component createAncestorComponent(Component parent, MavenDescriptor mavenDescriptor) {
		var component = new Component();
		component.setBomRef(parent.getBomRef() + "^");
		component.setType(Component.Type.LIBRARY);
		component.setName(mavenDescriptor.artifactId());
		component.setGroup(mavenDescriptor.groupId());
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
					var sourceBytes = byteCache.getBytes(uri,
							it -> getArtifactBytes(sourceArtifactDescriptor.getRepository(), sourceArtifactDescriptor));

					if (equivalent(bytes, sourceBytes, new ArrayList<>())) {
						basicLocation = sourceArtifactDescriptor.getRepository().getLocation();
					}
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}

		var location = getRedirectedURIForRedirections(basicLocation);
		var encodedLocation = urlEncodeQueryParameter(location.toString());
		var purl = "pkg:p2/" + artifactKey.getId() + "@" + artifactKey.getVersion() + "?classifier="
				+ artifactKey.getClassifier() + "&repository_url=" + encodedLocation;
		component.setPurl(purl);
	}

	private boolean setMavenPurl(Component component, MavenDescriptor mavenDescriptor, byte[] bytes) {
		try {
			// var xmlContent = contentHandler.getXMLContent(mavenDescriptor.toPOMURI());
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
			ancenstors.addComponent(createAncestorComponent(component, mavenDescriptor));
			pedigree.setAncestors(ancenstors);
			pedigree.setNotes(String.join(", ", differences));
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
			for (ArtifactSourceRepository repository : artifactSourceRepositories) {
				if (repository.contains(artifactDescriptor)) {
					return repository.uri();
				}
			}
		}
		// If not, use where we have fetched this from.
		return artifactDescriptor.getRepository().getLocation();
	}

	private URI getRedirectedURIForRedirections(URI location) {
		return getRedirectedURI(location, uriRedirections);
	}

	private void getClearlyDefinedProperty(Component component, MavenDescriptor mavenDescriptor) {
		if (!fetchClearlyDefined) {
			return;
		}
		if (!"sources".equals(mavenDescriptor.classifier())) {
			var clearlyDefinedURI = mavenDescriptor.toClearlyDefinedURI();
			// Submit async request to ClearlyDefinedApi
			clearlyDefinedApi.submitRequest(component, clearlyDefinedURI);
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
		var out = new ByteArrayOutputStream();
		var status = repository.getRawArtifact(artifactDescriptor, out, new NullProgressMonitor());
		if (!status.isOK()) {
			throw new RuntimeException(new CoreException(status));
		}
		return out.toByteArray();
	}

	private void gatherLicences(Component component, IInstallableUnit iu, IArtifactDescriptor artifactDescriptor,
			byte[] bytes) {
		var licenseToName = new TreeMap<String, String>();
		if (bytes.length > 2 && bytes[0] == 0x50 && bytes[1] == 0x4B) {
			gatherLicencesFromJar(component, bytes, licenseToName);
		}

		var mavenDescriptor = MavenDescriptor.create(iu, artifactDescriptor, bytes, queryCentral, contentHandler);
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
								} else if ("jquery.com/license/".equals(value) || "jquery.org/license".equals(value)) {
									value = "https://" + value;
								}
								if (!value.startsWith("http")) {
									var license = spdxIndex.getLicense(value);
									if (license != null) {
										licenseToName.put(license, value);
									} else {
										System.err.println("license=" + value);
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
											+ urlEncodeQueryParameter(eclipseSourceReferenceElement.getAttribute(key))))
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
					component.addProperty(createProperty("unsatisfied-requirement", requirement.toString()));
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

					var data = component.getData();
					if (data != null) {
						for (ComponentData componentData : component.getData()) {
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
}