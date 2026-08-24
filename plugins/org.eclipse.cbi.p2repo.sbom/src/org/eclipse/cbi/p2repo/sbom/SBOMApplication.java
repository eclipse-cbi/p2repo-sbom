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

import static org.eclipse.cbi.p2repo.sbom.ArgumentUtil.getArgument;
import static org.eclipse.cbi.p2repo.sbom.ArgumentUtil.getArguments;
import static org.eclipse.cbi.p2repo.sbom.URIUtil.parseRedirections;
import static org.eclipse.cbi.p2repo.sbom.URIUtil.toURI;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.NullProgressMonitor;
import org.eclipse.core.runtime.SubMonitor;
import org.eclipse.equinox.app.IApplication;
import org.eclipse.equinox.app.IApplicationContext;

public class SBOMApplication implements IApplication {

	private static final Pattern ARCHIVE_PATTERN = Pattern.compile("archive:(.*)!/.*");

	private static final URI SBOM_RENDERER_URI = URI.create("https://download.eclipse.org/cbi/sbom");

	@Override
	public Object start(IApplicationContext context) throws Exception {
		try {
			new Generator(getArguments(context)).generate(new NullProgressMonitor());
		} catch (Exception ex) {
			ex.printStackTrace();
			throw ex;
		}
		return EXIT_OK;
	}

	@Override
	public void stop() {
	}

	public static class Generator {
		private final List<String> originalArguments;

		private final Map<SBOMGenerator.Result, String> sbomGeneratorResults = new LinkedHashMap<>();

		public Generator(List<String> arguments) {
			originalArguments = new ArrayList<>(arguments);
		}

		public void generate(IProgressMonitor monitor) throws Exception {
			var args = new ArrayList<>(originalArguments);
			var verbose = getArgument("-verbose", args);
			if (verbose) {
				args.add(0, "-verbose");
				System.out.println("Application arguments: "
						+ args.stream().map(it -> '"' + it + '"').collect(Collectors.joining(" ")));
			}

			Path temporaryCache = null;
			if (!args.contains("-cache")) {
				temporaryCache = Files.createTempDirectory("org.eclipse.cbi.p2repo.sbom.cache");
				temporaryCache.toFile().deleteOnExit();
				var index = verbose ? 1 : 0;
				args.add(index, "-cache");
				args.add(index + 1, temporaryCache.toString());
			}

			var installationsFolder = getArgument("-installations", args, null);
			try {
				if (installationsFolder != null) {
					generateInstallations(installationsFolder, args, monitor);
				} else {
					var slices = getArguments("-slices", args, List.of());
					if (!slices.isEmpty()) {
						generateSlices(slices, args, monitor);
					} else {
						sbomGeneratorResults.put(new SBOMGenerator(args).generate(monitor), null);
					}
				}
			} finally {
				if (temporaryCache != null) {
					IOUtil.delete(temporaryCache);
				}
			}

			var index = getArgument("-index", args, null);
			if (index != null) {
				var indexPath = Path.of(index).toAbsolutePath();
				if (verbose) {
					System.out.println("Generating Index: " + index);
				}
				var render = getArgument("-renderer", args, SBOM_RENDERER_URI.toString());
				generateIndex(indexPath, URI.create(render), sbomGeneratorResults);

				var previewRedirections = parseRedirections(getArguments("-preview", args, List.of()));
				var redirectedIndex = previewRedirections.redirect(toURI(indexPath));
				if (!"file".equals(redirectedIndex.getScheme())) {
					URIUtil.openURL(redirectedIndex);
				}
			}
		}

		private void generateInstallations(String installationsFolder, List<String> args, IProgressMonitor monitor)
				throws Exception {
			var installationPattern = Pattern
					.compile(getArgument("-installation-pattern", args, ".*\\.(zip|tar|tar.gz)$"));
			var xmlOutputsFolder = getArgument("-xml-outputs", args, null);
			var jsonOutputsFolder = getArgument("-json-outputs", args, null);
			try (var contents = Files.newDirectoryStream(Path.of(installationsFolder).toAbsolutePath(),
					path -> installationPattern.matcher(path.getFileName().toString()).matches())) {
				var paths = StreamSupport.stream(contents.spliterator(), false).toList();
				var progress = SubMonitor.convert(monitor, paths.size());
				for (Path path : paths) {
					var effectiveArgs = new ArrayList<>(args);
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
					if (args.contains("-verbose")) {
						System.out.println("Generating for installation: " + path.toString());
					}
					sbomGeneratorResults.put(
							new SBOMGenerator(effectiveArgs).generate(progress.split(1, SubMonitor.SUPPRESS_NONE)),
							null);
				}
			}
		}

		private void generateSlices(List<String> slices, List<String> args, IProgressMonitor monitor) throws Exception {
			var xmlOutputsFolder = getArgument("-xml-outputs", args, null);
			var jsonOutputsFolder = getArgument("-json-outputs", args, null);
			var progress = SubMonitor.convert(monitor, slices.size());
			var SLICE_PATTERN = Pattern.compile("(?<name>.+)=(?<pattern>.+)");
			for (var slice : slices) {
				var matcher = SLICE_PATTERN.matcher(slice);
				if (!matcher.matches()) {
					throw new IllegalAccessException("Expecting name=pattern: " + slice);
				}
				var name = matcher.group("name");
				var pattern = matcher.group("pattern");

				var effectiveArgs = new ArrayList<>(args);
				effectiveArgs.add("-root-iu-inclusions");
				effectiveArgs.add(pattern);
				if (xmlOutputsFolder != null) {
					effectiveArgs.add("-xml-output");
					effectiveArgs.add(xmlOutputsFolder + "/" + name + "-sbom.xml");
				}
				if (jsonOutputsFolder != null) {
					effectiveArgs.add("-json-output");
					effectiveArgs.add(xmlOutputsFolder + "/" + name + "-sbom.json");
				}
				if (args.contains("-verbose")) {
					System.out.println("Generating for slice: " + slice);
				}
				sbomGeneratorResults.put(
						new SBOMGenerator(effectiveArgs).generate(progress.split(1, SubMonitor.SUPPRESS_NONE)), name);
			}
		}

		private void generateIndex(Path indexPath, URI renderer, Map<SBOMGenerator.Result, String> sbomGeneratorResults)
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
								td {
									vertical-align: top;
								}

							</style>
					</head>
					<body>
						<table>
							${items}
						</table>

						<details>
							<summary>Arguments</summary>
							<pre>${args}</pre>
						</details>

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
			html = html.replace("${args}", toString(originalArguments));

			var items = new ArrayList<String>();
			for (var entry : sbomGeneratorResults.entrySet()) {
				var sbomGenerator = entry.getKey();
				var content = new ArrayList<String>();
				content.add("""
						<td>
							<details>
								<summary></summary>
								<pre style="font-size: 85%">${args}</pre>
							</details>
						</td>
						""".replace("${args}", toString(sbomGenerator.arguments())));

				var inputs = sbomGenerator.inputs();
				var inputLinks = inputs.stream().map(Generator::toLink)
						.collect(Collectors.joining("<br/>", "<td>", "</td>"));
				content.add(inputLinks);

				var name = entry.getValue();
				if (name != null) {
					content.add("<td><b>" + name + "</b></td>");
				}

				var outputs = sbomGenerator.outputs();
				for (var output : outputs) {
					var relativePath = indexPath.getParent().relativize(output).toString();
					var label = relativePath.endsWith(".json") ? "json" : "xml";
					var hrefs = """
							<td>
								<a href="${renderer}/?file=${file}"><img src="https://img.shields.io/static/v1?logo=eclipseide&label=Rendered&message=${label}&style=for-the-badge&logoColor=gray&labelColor=rgb(255,164,44)&color=gray"/></a>
							</td>
							<td>
								<a href="${file}"><img src="https://img.shields.io/static/v1?logo=eclipseide&label=Raw&message=${label}&style=for-the-badge&logoColor=gray&labelColor=rgb(255,164,44)&color=gray"/></a>
							</td>
							""";
					hrefs = hrefs //
							.replace("${renderer}", renderer.toString()) //
							.replace("${file}", relativePath) //
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

		private static String toString(List<String> arguments) {
			return arguments.stream().map(it -> !it.startsWith("-") ? "  " + it : it)
					.collect(Collectors.joining("&#10;"));
		}

		private static String toLink(URI uri) {
			var value = uri.toString();
			var archiveMatcher = ARCHIVE_PATTERN.matcher(value);
			var baseURI = archiveMatcher.matches() ? archiveMatcher.group(1) : value;
			return "<a href='" + baseURI + "'>" + baseURI + "</a>";
		}
	}
}