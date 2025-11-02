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

import static org.eclipse.cbi.p2repo.sbom.BOMUtil.urlEncodeQueryParameter;
import static org.eclipse.cbi.p2repo.sbom.IOUtil.toInterruptedIOException;
import static org.eclipse.cbi.p2repo.sbom.XMLUtil.newDocumentBuilder;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class ContentHandler {

	public static class ContentHandlerException extends IOException {
		private static final long serialVersionUID = 1L;

		private final int statusCode;

		private String retryAfter;

		public ContentHandlerException(HttpResponse<?> response) {
			super("status code " + response.statusCode() + " -> " + response.uri());
			this.statusCode = response.statusCode();
			retryAfter = response.headers().firstValue("Retry-After").orElse(null);
		}

		public ContentHandlerException(int statusCode, URI uri) {
			super("status code " + statusCode + " -> " + uri);
			this.statusCode = statusCode;
		}

		public int statusCode() {
			return statusCode;
		}

		public int getRetryAfter() {
			try {
				if (retryAfter != null) {
					return Integer.parseInt(retryAfter);
				}
			} catch (NumberFormatException e) {
				// it could be a date... not supported yet!
				System.err.println("Can't parse retry header: " + retryAfter + " using default of 5 seconds!");
			}
			return 5; // default 5 seconds
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
		var request = newRequest(uri);
		var response = httpClient.send(request, bodyHandler);
		var statusCode = response.statusCode();
		if (statusCode != 200) {
			throw new ContentHandlerException(response);
		}
		return response.body();
	}

	private HttpRequest newRequest(URI uri) {
		var fragment = uri.getFragment();
		if (fragment == null) {
			return HttpRequest.newBuilder(uri).GET().build();
		}
		var baseURI = URI.create(uri.toString().replaceAll("#.*$", ""));
		var parts = new ArrayList<>(List.of(fragment.split(",")));
		var body = parts.remove(parts.size() - 1);
		var headers = parts.toArray(String[]::new);
		return HttpRequest.newBuilder(baseURI).headers(headers).POST(BodyPublishers.ofString(body)).build();
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

	public Path getCachePath404(URI uri) {
		return getCachePath(uri, "404/");
	}

	public Path getCachePath(URI uri) {
		return getCachePath(uri, "");
	}

	private Path getCachePath(URI uri, String prefix) {
		var decodedURI = URLDecoder.decode(uri.toString(), StandardCharsets.UTF_8);
		var uriSegments = decodedURI.split("[:/?#&;,{}'\"]+");
		uriSegments[uriSegments.length - 1] = "_" + uriSegments[uriSegments.length - 1];
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

	public String getPostContent(URI uri, List<String> headers, String body) throws IOException {
		return getContent(URI.create(
				uri + "#" + headers.stream().map(BOMUtil::urlEncodeQueryParameter).collect(Collectors.joining(","))
						+ "," + urlEncodeQueryParameter(body)));
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
		var retry = 5;
		while (!Thread.currentThread().isInterrupted()) {
			try {
				Files.createDirectories(path.getParent());
				var content = basicGetContent(uri, bodyHandler);
				writer.write(path, content);
				return content;
			} catch (ContentHandlerException e) {
				var statusCode = e.statusCode();
				if (statusCode == 404) {
					Files.createDirectories(path404.getParent());
					Files.writeString(path404, "");
				}
				if (retry-- > 0 && retryRequest(statusCode)) {
					try {
						var retryAfter = e.getRetryAfter();
						System.err.println("## Request to " + uri + " failed, retry again after " + retryAfter
								+ " seconds [" + retry + " retries left]");
						TimeUnit.SECONDS.sleep(retryAfter);
					} catch (InterruptedException e1) {
						throw toInterruptedIOException(e1);
					}
					continue;
				}
				throw e;

			} catch (InterruptedException e) {
				throw toInterruptedIOException(e);
			}
		}
		throw new InterruptedIOException("Failed after " + retry + " retries: " + uri);
	}

	private boolean retryRequest(int statusCode) {
		return statusCode == 429 /* To many Requests */ || statusCode == 503 /* Service unavailable */
				|| statusCode == 502 /* Bad Gateway */ || statusCode == 504 /* Gateway timeout */
				|| statusCode == 524 /* Cloudflare-specific timeout */;
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