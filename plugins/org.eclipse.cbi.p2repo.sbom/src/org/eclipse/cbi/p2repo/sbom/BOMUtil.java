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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.xml.stream.XMLOutputFactory;

import org.cyclonedx.Version;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.generators.xml.BomXmlGenerator;
import org.cyclonedx.model.Annotation;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.Property;

import com.ctc.wstx.stax.WstxOutputFactory;

public final class BOMUtil {
	private static final List<String> ALGORITHMS = List.of("MD5", "SHA-1", "SHA-256", "SHA-512", "SHA-384", "SHA3-256",
			"SHA3-384", "SHA3-512");

	private static final Collector<CharSequence, ?, String> INDENTED_PROPERTY_VALUE_COLLECTOR = Collectors
			.joining("\n      ", "\n      ", "\n    ");

	private BOMUtil() {
		throw new UnsupportedOperationException("Do not instantiate");
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

	public static void addHashes(Component component, byte[] bytes) {
		Map<String, Hash> hashes = ALGORITHMS.parallelStream()
				.map(algorithm -> new Hash(algorithm, computeHash(algorithm, bytes)))
				.collect(Collectors.toMap(Hash::getAlgorithm, Function.identity()));
		for (String algorithm : ALGORITHMS) {
			component.addHash(hashes.get(algorithm));
		}
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
		// Same for ! which we use for archive URIs when building an SBOM for a product
		// in a *.zip/*.tar.gz.
		var result = URLEncoder.encode(value, StandardCharsets.UTF_8);
		return result.replace("%2F", "/").replace("%3A", ":").replace("%21", "!");
	}
}