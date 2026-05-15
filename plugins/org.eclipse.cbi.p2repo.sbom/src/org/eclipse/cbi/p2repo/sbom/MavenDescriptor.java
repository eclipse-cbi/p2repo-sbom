/**
 * Copyright (c) 2025 Eclipse contributors and others.
 *
 * This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.eclipse.cbi.p2repo.sbom;

import static org.eclipse.cbi.p2repo.sbom.BOMUtil.computeHash;
import static org.eclipse.cbi.p2repo.sbom.XMLUtil.evaluate;
import static org.eclipse.cbi.p2repo.sbom.XMLUtil.newDocumentBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.jar.JarInputStream;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;

import javax.xml.parsers.ParserConfigurationException;

import org.eclipse.equinox.p2.metadata.IInstallableUnit;
import org.eclipse.equinox.p2.repository.artifact.IArtifactDescriptor;
import org.json.JSONObject;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public final record MavenDescriptor(String groupId, String artifactId, String version, String classifier, String type) {

	public static final String MAVEN_CENTRAL_URI = "https://repo.maven.apache.org/maven2/";

	private static final Pattern JAR_ARTIFACT_PATTERN = Pattern
			.compile("(.*/)?(?<artifactId>[^-]+)-(?<version>([0-9.]+[^-]+)?)(-(?<classifier>[^-0-9]+))?\\.jar");

	public static MavenDescriptor create(IInstallableUnit iu, IArtifactDescriptor artifactDescriptor, byte[] bytes,
			boolean queryCentral, ContentHandler contentHandler) {
		var mavenDescriptor = create(artifactDescriptor.getProperties());
		if (mavenDescriptor == null) {
			mavenDescriptor = create(iu.getProperties());
		}
		if (mavenDescriptor == null && bytes.length != 0) {
			mavenDescriptor = createFromBytes(bytes, queryCentral, contentHandler);
		}
		return mavenDescriptor;
	}

	public static MavenDescriptor createFromJarName(String jarName, boolean queryCentral,
			ContentHandler contentHandler) {
		if (!queryCentral) {
			return null;
		}

		var matcher = JAR_ARTIFACT_PATTERN.matcher(jarName);
		if (matcher.matches()) {
			try {
				var artifactId = "a:" + matcher.group("artifactId");
				var version = "v:" + matcher.group("version");
				var classifier = matcher.group("classifier");
				var parts = classifier == null ? List.of(artifactId, version)
						: List.of(artifactId, version, "l:" + classifier);
				var query = "https://search.maven.org/solrsearch/select?q=" + String.join("%20AND%20", parts)
						+ "&rows=20&wt=json";
				var queryResult = contentHandler.getContent(URI.create(query));
				var jsonObject = new JSONObject(queryResult);
				if (jsonObject.has("response")) {
					var response = jsonObject.getJSONObject("response");
					if (response.has("numFound") && response.getInt("numFound") == 1) {
						var coordinates = response.getJSONArray("docs").getJSONObject(0);
						return new MavenDescriptor(coordinates.getString("g"), coordinates.getString("a"),
								coordinates.getString("v"), classifier, coordinates.getString("p"));
					}
				}
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		return null;
	}

	public static MavenDescriptor createFromPOM(byte[] bytes) {
		try {
			var builder = newDocumentBuilder();
			var document = builder.parse(new InputSource(new ByteArrayInputStream(bytes)));
			var groupIds = evaluate(document,
					"/pom:project/pom:groupId|/project/groupId|/pom:project/pom:parent/pom:groupId|project/parent/groupId");
			if (groupIds.size() > 0) {
				var groupId = groupIds.get(groupIds.size() - 1).getTextContent();
				var artifactIds = evaluate(document, "/pom:project/pom:artifactId|/project/artifactId");
				var versions = evaluate(document, "/pom:project/pom:version|/project/version");
				if (!artifactIds.isEmpty() && !versions.isEmpty()) {
					return new MavenDescriptor(groupId, artifactIds.get(0).getTextContent(),
							versions.get(0).getTextContent(), null, "jar");
				}
			}
		} catch (RuntimeException ex) {
			throw ex;
		} catch (ParserConfigurationException | SAXException | IOException ex) {
			throw new RuntimeException(ex);
		}
		return null;
	}

	public static MavenDescriptor createFromBytes(byte[] bytes, boolean queryCentral, ContentHandler contentHandler) {
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
			throw new RuntimeException(e);
		}

		if (queryCentral) {
			// This is not the end we can try to query maven central
			try {
				var sha1Hash = computeHash("SHA-1", bytes);
				var query = "https://central.sonatype.com/solrsearch/select?q=1:" + sha1Hash + "&wt=json";
				var queryResult = contentHandler.getContent(URI.create(query));
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
				throw new RuntimeException(e);
			}
		}
		return null;
	}

	public static MavenDescriptor create(Map<String, String> properties) {
		var mavenDescriptor = create(properties.get("maven-wrapped-groupId"),
				properties.get("maven-wrapped-artifactId"), properties.get("maven-wrapped-version"),
				properties.get("maven-wrapped-classifier"), properties.get("maven-wrapped-type"));
		return mavenDescriptor != null ? mavenDescriptor
				: create(properties.get("maven-groupId"), properties.get("maven-artifactId"),
						properties.get("maven-version"), properties.get("maven-classifier"),
						properties.get("maven-type"));
	}

	public static MavenDescriptor create(String mavenGroupId, String mavenArtifactId, String mavenVersion,
			String mavenClassifier, String mavenType) {
		if (mavenGroupId != null && mavenArtifactId != null && mavenVersion != null) {
			return new MavenDescriptor(mavenGroupId, mavenArtifactId, mavenVersion,
					mavenClassifier == null || mavenClassifier.isBlank() ? null : mavenClassifier,
					mavenType == null || mavenType.isBlank() || mavenType.contains("-") ? "jar" : mavenType);
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
		return URI.create("https://api.clearlydefined.io/definitions/maven/mavencentral/" + groupId + "/" + artifactId
				+ "/" + version);
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
		return URI.create(MAVEN_CENTRAL_URI + groupId.replace('.', '/') + "/" + artifactId + "/" + version + "/"
				+ artifactId + "-" + version + suffix);
	}
}