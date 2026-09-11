package org.eclipse.cbi.p2repo.sbom;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public final class XMLUtil {

	private static final XPathFactory XPATH_FACTORY = XPathFactory.newInstance();

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

	/**
	 * Returns the text content of the first direct child element with the given
	 * local name, or {@code null} if none exists. Unlike {@link #getText}, this
	 * does not recurse into nested descendants - critical when extracting POM
	 * fields where a nested {@code <url>} inside a plugin {@code <configuration>}
	 * would otherwise shadow a missing top-level {@code <project>/<url>}.
	 */
	public static String getDirectChildText(Element element, String name) {
		var children = element.getChildNodes();
		for (int i = 0, length = children.getLength(); i < length; i++) {
			var node = children.item(i);
			if (node.getNodeType() == Node.ELEMENT_NODE && name.equals(node.getLocalName())) {
				return node.getTextContent();
			}
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