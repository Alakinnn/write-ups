# Intro to XSLT Injection

---

[eXtensible Stylesheet Language Transformation (XSLT)](https://www.w3.org/TR/xslt-30/) is a language enabling the transformation of XML documents. For instance, it can select specific nodes from an XML document and change the XML structure.

---

## eXtensible Stylesheet Language Transformation (XSLT)

Since XSLT operates on XML-based data, we will consider the following sample XML document to explore how XSLT operates:

Code: xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<fruits>
    <fruit>
        <name>Apple</name>
        <color>Red</color>
        <size>Medium</size>
    </fruit>
    <fruit>
        <name>Banana</name>
        <color>Yellow</color>
        <size>Medium</size>
    </fruit>
    <fruit>
        <name>Strawberry</name>
        <color>Red</color>
        <size>Small</size>
    </fruit>
</fruits>
```

XSLT can be used to define a data format which is subsequently enriched with data from the XML document. XSLT data is structured similarly to XML. However, it contains XSL elements within nodes prefixed with the `xsl`-prefix. The following are some commonly used XSL elements:

- `<xsl:template>`: This element indicates an XSL template. It can contain a `match` attribute that contains a path in the XML document that the template applies to
- `<xsl:value-of>`: This element extracts the value of the XML node specified in the `select` attribute
- `<xsl:for-each>`: This element enables looping over all XML nodes specified in the `select` attribute

For instance, a simple XSLT document used to output all fruits contained within the XML document as well as their color, may look like this:

Code: xslt

```xslt
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:template match="/fruits">
		Here are all the fruits:
		<xsl:for-each select="fruit">
			<xsl:value-of select="name"/> (<xsl:value-of select="color"/>)
		</xsl:for-each>
	</xsl:template>
</xsl:stylesheet>
```

As we can see, the XSLT document contains a single `<xsl:template>` XSL element that is applied to the `<fruits>` node in the XML document. The template consists of the static string `Here are all the fruits:` and a loop over all `<fruit>` nodes in the XML document. For each of these nodes, the values of the `<name>` and `<color>` nodes are printed using the `<xsl:value-of>` XSL element. Combining the sample XML document with the above XSLT data results in the following output:

```
Here are all the fruits:
    Apple (Red)
    Banana (Yellow)
    Strawberry (Red)
```

Here are some additional XSL elements that can be used to narrow down further or customize the data from an XML document:

- `<xsl:sort>`: This element specifies how to sort elements in a for loop in the `select` argument. Additionally, a sort order may be specified in the `order` argument
    
- `<xsl:if>`: This element can be used to test for conditions on a node. The condition is specified in the `test` argument.
    

For instance, we can use these XSL elements to create a list of all fruits that are of a medium size ordered by their color in descending order:

Code: xslt

```xslt
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:template match="/fruits">
		Here are all fruits of medium size ordered by their color:
		<xsl:for-each select="fruit">
			<xsl:sort select="color" order="descending" />
			<xsl:if test="size = 'Medium'">
				<xsl:value-of select="name"/> (<xsl:value-of select="color"/>)
			</xsl:if>
		</xsl:for-each>
	</xsl:template>
</xsl:stylesheet>
```

This results in the following data:

```
Here are all fruits of medium size ordered by their color:
	Banana (Yellow)
	Apple (Red)
```

XSLT can be used to generate arbitrary output strings. For instance, web applications may use it to embed data from XML documents within an HTML response.

---

## XSLT Injection

As the name suggests, XSLT injection occurs whenever user input is inserted into XSL data before output generation by the XSLT processor. This enables an attacker to inject additional XSL elements into the XSL data, which the XSLT processor will execute during output generation.

# Exploiting XSLT Injection

---

After discussing some basics and use cases for XSLT, let us dive into exploiting XSLT injection vulnerabilities. 

---

## Identifying XSLT Injection

Our sample web application displays basic information about some Academy modules:

   

![](https://academy.hackthebox.com/storage/modules/145/xslt/xslt_exploitation_1.png)

At the bottom of the page, we can provide a username that is inserted into the headline at the top of the list:

   

![](https://academy.hackthebox.com/storage/modules/145/xslt/xslt_exploitation_2.png)

As we can see, the name we provide is reflected on the page. Suppose the web application stores the module information in an XML document and displays the data using XSLT processing. In that case, it might suffer from XSLT injection if our name is inserted without sanitization before XSLT processing. To confirm that, let us try to inject a broken XML tag to try to provoke an error in the web application. We can achieve this by providing the username `<`:

   

![](https://academy.hackthebox.com/storage/modules/145/xslt/xslt_exploitation_3.png)

As we can see, the web application responds with a server error. While this does not confirm that an XSLT injection vulnerability is present, it might indicate the presence of a security issue.

---

## Information Disclosure

We can try to infer some basic information about the XSLT processor in use by injecting the following XSLT elements:

Code: xml

```xml
Version: <xsl:value-of select="system-property('xsl:version')" />
<br/>
Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
<br/>
Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
<br/>
Product Name: <xsl:value-of select="system-property('xsl:product-name')" />
<br/>
Product Version: <xsl:value-of select="system-property('xsl:product-version')" />
```

The web application provides the following response:

   

![](https://academy.hackthebox.com/storage/modules/145/xslt/xslt_exploitation_4.png)

Since the web application interpreted the XSLT elements we provided, this confirms an XSLT injection vulnerability. Furthermore, we can deduce that the web application seems to rely on the `libxslt` library and supports XSLT version `1.0`.

---

## Local File Inclusion (LFI)

We can try to use multiple different functions to read a local file. Whether a payload will work depends on the XSLT version and the configuration of the XSLT library. For instance, XSLT contains a function `unparsed-text` that can be used to read a local file:

Code: xml

```xml
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')" />
```

However, it was only introduced in XSLT version 2.0. Thus, our sample web application does not support this function and instead errors out. However, if the XSLT library is configured to support PHP functions, we can call the PHP function `file_get_contents` using the following XSLT element:

Code: xml

```xml
<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />
```

Our sample web application is configured to support PHP functions. As such, the local file is displayed in the response:

   

![](https://academy.hackthebox.com/storage/modules/145/xslt/xslt_exploitation_5.png)

---

## Remote Code Execution (RCE)

If an XSLT processor supports PHP functions, we can call a PHP function that executes a local system command to obtain RCE. For instance, we can call the PHP function `system` to execute a command:

Code: xml

```xml
<xsl:value-of select="php:function('system','id')" />
```

   

![](https://academy.hackthebox.com/storage/modules/145/xslt/xslt_exploitation_6.png)

# Preventing XSLT Injection

---

After discussing how to identify and exploit XSLT injection vulnerabilities in the previous sections, we will conclude this module by discussing how to prevent them.

---

## Prevention

Similarly to all injection vulnerabilities discussed in this module, XSLT injection can be prevented by ensuring that user input is not inserted into XSL data before processing by the XSLT processor. However, if the output should reflect values provided by the user, user-provided data might be required to be added to the XSL document before processing. In this case, it is essential to implement proper sanitization and input validation to avoid XSLT injection vulnerabilities. This may prevent attackers from injecting additional XSLT elements, but the implementation may depend on the output format.

For instance, if the XSLT processor generates an HTML response, HTML-encoding user input before inserting it into the XSL data can prevent XSLT injection vulnerabilities. As HTML-encoding converts all instances of `<` to `&lt;` and `>` to `&gt;`, an attacker should not be able to inject additional XSLT elements, thus preventing an XSLT injection vulnerability.

Additional hardening measures such as running the XSLT processor as a low-privilege process, preventing the use of external functions by turning off PHP functions within XSLT, and keeping the XSLT library up-to-date can mitigate the impact of potential XSLT injection vulnerabilities.
