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
package org.eclipse.cbi.p2repo.sbom.tests;

import java.util.Arrays;

import org.cyclonedx.Version;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Hash;
import org.eclipse.cbi.p2repo.sbom.SBOMApplication;
import org.junit.jupiter.api.Test;

public class SBOMTest {

	@Test
	public void test() throws Exception {
		var extRef = new ExternalReference();
		extRef.setType(ExternalReference.Type.BOM);
		extRef.setUrl("https://example.org/support/sbom/portal-server/1.0.0");
		extRef.setComment("An external SBOM that describes what this component includes");
		var md5 = new Hash(Hash.Algorithm.MD5, "2cd42512b65500dc7ba0ff13490b0b73");
		var sha1 = new Hash(Hash.Algorithm.SHA1, "226247b40160f2892fa4c7851b5b913d5d10912d");
		var sha256 = new Hash(Hash.Algorithm.SHA_256,
				"09a72795a920c1a9c0209cfb8395f8d97089832d249cba8c0938a3423b3ed1d1");
		extRef.setHashes(Arrays.asList(md5, sha1, sha256));

		var component = new Component();
		component.setGroup("org.example");
		component.setName("mylibrary");
		component.setType(Component.Type.LIBRARY);
		component.setVersion("1.0.0");
		component.addExternalReference(extRef);

		var bom = new Bom();
		bom.addComponent(component);

		var xmlGenerator = SBOMApplication.BOMUtil.createBomXMLGenerator(Version.VERSION_16, bom);
		var xmlString = xmlGenerator.toXmlString();
		System.out.println(xmlString);

		var jsonGenerator = BomGeneratorFactory.createJson(Version.VERSION_16, bom);
		var jsonString = jsonGenerator.toJsonString();
		System.out.println(jsonString);
	}

	@Test
	public void testCPESupport() throws Exception {
		// Test that CPE field is supported in CycloneDX Component model
		var component = new Component();
		component.setGroup("org.apache.commons");
		component.setName("commons-logging");
		component.setType(Component.Type.LIBRARY);
		component.setVersion("1.2");
		
		// Set a CPE identifier
		String cpe = "cpe:2.3:a:apache:commons_logging:1.2:*:*:*:*:*:*:*";
		component.setCpe(cpe);
		
		var bom = new Bom();
		bom.addComponent(component);

		// Verify CPE is included in JSON output
		var jsonGenerator = BomGeneratorFactory.createJson(Version.VERSION_16, bom);
		var jsonString = jsonGenerator.toJsonString();
		System.out.println("CPE Test JSON Output:");
		System.out.println(jsonString);
		
		// Basic verification that CPE is present
		if (!jsonString.contains("\"cpe\"")) {
			throw new AssertionError("CPE field not found in JSON output");
		}
		if (!jsonString.contains(cpe)) {
			throw new AssertionError("CPE value not found in JSON output");
		}

		// Verify CPE is included in XML output
		var xmlGenerator = SBOMApplication.BOMUtil.createBomXMLGenerator(Version.VERSION_16, bom);
		var xmlString = xmlGenerator.toXmlString();
		System.out.println("CPE Test XML Output:");
		System.out.println(xmlString);
		
		if (!xmlString.contains("<cpe>")) {
			throw new AssertionError("CPE element not found in XML output");
		}
		if (!xmlString.contains(cpe)) {
			throw new AssertionError("CPE value not found in XML output");
		}
	}

}
