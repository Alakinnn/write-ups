# Local DTD Files Wordlist for XXE Testing

This wordlist contains paths to common local DTD files found in various operating systems and applications that might be useful for exploiting XXE vulnerabilities through DTD repurposing.

## Linux/Unix Systems

```
/usr/share/yelp/dtd/docbookx.dtd
/usr/share/xml/docbook/schema/dtd/4.5/docbookx.dtd
/usr/share/xml/docbook/schema/dtd/4.4/docbookx.dtd
/usr/share/xml/docbook/schema/dtd/4.3/docbookx.dtd
/usr/share/xml/docbook/schema/dtd/4.2/docbookx.dtd
/usr/share/xml/docbook/schema/dtd/4.1.2/docbookx.dtd
/usr/share/xml/docbook/custom/dtd/xml/4.5/docbookx.dtd
/usr/share/sgml/docbook/dtd/xml/4.5/docbookx.dtd
/usr/share/sgml/docbook/dtd/xml/4.4/docbookx.dtd
/usr/share/sgml/docbook/dtd/xml/4.3/docbookx.dtd
/usr/share/sgml/docbook/dtd/xml/4.2/docbookx.dtd
/usr/share/sgml/docbook/dtd/xml/4.1.2/docbookx.dtd
/usr/share/sgml/docbook/xml-dtd-4.5/docbookx.dtd
/usr/share/sgml/docbook/xml-dtd-4.4/docbookx.dtd
/usr/share/sgml/docbook/xml-dtd-4.3/docbookx.dtd
/usr/share/sgml/docbook/xml-dtd-4.2/docbookx.dtd
/usr/share/sgml/docbook/xml-dtd-4.1.2/docbookx.dtd
/etc/xml/docbook-xml/4.5/dtd/docbookx.dtd
/etc/xml/docbook-xml/4.4/dtd/docbookx.dtd
/etc/xml/docbook-xml/4.3/dtd/docbookx.dtd
/etc/xml/docbook-xml/4.2/dtd/docbookx.dtd
/usr/local/share/xml/docbook/4.5/docbookx.dtd
/usr/local/share/xml/docbook/4.4/docbookx.dtd
/usr/local/share/xml/docbook/4.3/docbookx.dtd
/usr/local/share/xml/docbook/4.2/docbookx.dtd
/usr/share/xml/xhtml/xhtml1-strict.dtd
/usr/share/xml/xhtml/xhtml1-transitional.dtd
/usr/share/xml/xhtml/xhtml1-frameset.dtd
/usr/share/xml/xhtml/1.0/DTD/xhtml1-strict.dtd
/usr/share/xml/xhtml/1.0/DTD/xhtml1-transitional.dtd
/usr/share/xml/xhtml/1.0/DTD/xhtml1-frameset.dtd
/usr/share/xml/svg/1.1/svg11.dtd
/usr/share/xml/svg/1.0/svg10.dtd
/usr/share/xml/mathml/schema/dtd/3.0/mathml3.dtd
/usr/share/xml/mathml/schema/dtd/2.0/mathml2.dtd
/usr/share/xml/tei/schema/dtd/tei_all.dtd
/usr/share/xml/entities/xml-iso-entities/iso-tex.ent
/usr/share/xml/schema/xml-core/catalog.dtd
/usr/share/doc/libxml2-utils/examples/small.dtd
/usr/share/gtksourceview-3.0/language-specs/dtd.lang
```

## Java/Apache Based Systems

```
/usr/local/tomcat/lib/jsp-api.jar!/javax/servlet/jsp/resources/jsp_2_0.dtd
/usr/local/tomcat/lib/servlet-api.jar!/javax/servlet/resources/web-app_2_3.dtd
/usr/local/tomcat/lib/jsp-api.jar!/javax/servlet/jsp/resources/jsp_2_2.dtd
/usr/local/tomcat/lib/servlet-api.jar!/javax/servlet/resources/web-app_3_0.dtd
/usr/share/java/jsp-api-*.jar!/javax/servlet/jsp/resources/jsp_2_0.dtd
/usr/share/java/servlet-api-*.jar!/javax/servlet/resources/web-app_2_3.dtd
/opt/tomcat/lib/jsp-api.jar!/javax/servlet/jsp/resources/jsp_2_0.dtd
/opt/tomcat/lib/servlet-api.jar!/javax/servlet/resources/web-app_2_3.dtd
/var/lib/tomcat*/lib/jsp-api.jar!/javax/servlet/jsp/resources/jsp_2_0.dtd
/var/lib/tomcat*/lib/servlet-api.jar!/javax/servlet/resources/web-app_2_3.dtd
/opt/jboss/standalone/deployments/ROOT.war/WEB-INF/web.dtd
/opt/app/application/WEB-INF/web.dtd
/usr/share/java/ant-1.*/lib/ant.dtd
/usr/share/xml/maven/maven-catalog-plugin-1.0.dtd
/usr/local/maven/conf/catalog-1.0.dtd
/usr/share/maven2/plugin/catalog-1.0.dtd
```

## Microsoft Windows Systems

```
C:\Windows\System32\drivers\etc\protocol.dtd
C:\Windows\System32\inetsrv\config\schema\IIS_schema.xml
C:\Program Files\Microsoft Office\Office*/XMLMAPPING\SCHEMA.DTD
C:\Program Files\Microsoft Office\root\Office*\SCHEMA.DTD
C:\Program Files (x86)\Microsoft Office\Office*/XMLMAPPING\SCHEMA.DTD
C:\Program Files (x86)\Microsoft Office\root\Office*\SCHEMA.DTD
C:\Program Files\Microsoft SQL Server\*\Shared\sqlresld.dtd
C:\Program Files\Microsoft SQL Server\*\Tools\binn\schemas\sqlresources\sql-main-80.dtd
C:\Program Files\Microsoft Visual Studio *\Common7\IDE\Extensions\Microsoft\SQLDB\Extensions\Server\*\SqlWorkbench.dtd
C:\Program Files (x86)\Microsoft Visual Studio *\Common7\IDE\Extensions\Microsoft\SQLDB\Extensions\Server\*\SqlWorkbench.dtd
C:\Windows\Microsoft.NET\Framework\v*\CONFIG\web_1_0.dtd
C:\Windows\Microsoft.NET\Framework\v*\CONFIG\web_2_0.dtd
C:\Windows\Microsoft.NET\Framework\v*\CONFIG\web_3_0.dtd
C:\Windows\Microsoft.NET\Framework\v*\CONFIG\web.dtd
C:\Windows\System32\msxml4.dll
C:\Windows\System32\msxml6.dll
C:\Windows\System32\URLMON.DLL
```

## Common CMS Systems

```
/var/www/html/wordpress/wp-content/plugins/docxpressoPlugin/core/DocxpressoPlugin.dtd
/var/www/html/wordpress/wp-content/plugins/wp-dtd-parser/libs/dtd-parser.dtd
/var/www/html/drupal/modules/system/system.dtd
/var/www/html/drupal/core/lib/Drupal/Core/Entity/entity.dtd
/var/www/html/joomla/libraries/vendor/joomla/registry/src/format/xml/registry.dtd
/usr/share/drupal*/modules/system/system.dtd
/usr/share/wordpress/wp-content/plugins/docxpressoPlugin/core/DocxpressoPlugin.dtd
```

## Application-Specific DTDs

```
/opt/atlassian/jira/lib/catalina.jar!/javax/servlet/resources/web-app_2_3.dtd
/opt/atlassian/confluence/lib/catalina.jar!/javax/servlet/resources/web-app_2_3.dtd
/usr/share/eclipse/plugins/org.eclipse.wst.dtd.core_*.jar!/dtdsource/datatypes.dtd
/usr/share/sgml/html/4.01/html4.dtd
/usr/share/xml/fontconfig/fonts.dtd
/usr/share/texlive/texmf-dist/tex/latex/base/ltx-article.dtd
/opt/libreoffice*/share/dtd/officedocument/1_0/office.dtd
/opt/openoffice*/share/dtd/officedocument/1_0/office.dtd
/usr/lib*/openoffice/share/dtd/officedocument/1_0/office.dtd
/usr/share/cups/mime/mime.dtd
/usr/share/kde4/apps/ksgmltools2/customization/dtd/kdedbx45.dtd
/opt/IBM/WebSphere/AppServer/properties/version/dtd/properties.dtd
/opt/oracle/product/*/dbhome/rdbms/admin/catexp.dtd
/usr/share/libgda-5.0/dtd/libgda-array.dtd
/usr/share/yelp/dtd/docbookx.dtd
```

## Testing Techniques

When testing for XXE vulnerabilities using local DTD files:

1. Try using the SYSTEM identifier with these paths
2. Use parameter entities to reference external DTDs
3. Observe for error messages that might reveal if the file exists
4. Test for outbound connections to detect successful exploitation

Remember that successful exploitation depends on:

- The XML parser being configured to allow DTD processing
- The application server having access to these local files
- The specific DTD having exploitable entities that can be repurposed

This wordlist should provide a good starting point for testing XXE vulnerabilities through DTD repurposing.